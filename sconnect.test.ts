import { describe, it, expect } from "vitest";
import {
	blind,
	cipher,
	deBlind,
	dh,
	generateKeyPair,
	generateSigningKeyPair,
	SConnect,
	sigh,
	verifySignature,
} from "./sconnect";
import {
	LoopbackAdapterManager,
	UntrustedLoopbackAdapterManager,
} from "./loopback_adapter";
import type { ConnectRequest, PairRequest } from "./sconnect_type";

function waitForEvent<T extends any[], E extends string>(
	emitter: { on: (event: E, cb: (...args: T) => void) => void },
	event: E,
	timeout = 5000,
): Promise<T> {
	return new Promise((resolve, reject) => {
		const timer = setTimeout(
			() => reject(new Error(`Timeout waiting for ${event}`)),
			timeout,
		);
		emitter.on(event, (...args: T) => {
			clearTimeout(timer);
			resolve(args);
		});
	});
}

describe("SConnect", () => {
	describe("受信任信道 (trustIdentity=true)", () => {
		it("应直接建立明文连接", async () => {
			const [adapterA, adapterB] = LoopbackAdapterManager.createPair();
			const channelA = new SConnect(adapterA);
			const channelB = new SConnect(adapterB);

			await channelA.init("device-a", "device-b");
			await channelB.init("device-b", "device-a");

			const [resultA, resultB] = await Promise.all([
				channelA.tryConnect(),
				channelB.tryConnect(),
			]);

			expect(resultA.success).toBe(true);
			expect(resultB.success).toBe(true);

			channelA.disconnect();
			channelB.disconnect();
		});

		it("消息应为明文（不加密）", async () => {
			const [adapterA, adapterB] = LoopbackAdapterManager.createPair();
			const channelA = new SConnect(adapterA);
			const channelB = new SConnect(adapterB);

			await channelA.init("device-a", "device-b");
			await channelB.init("device-b", "device-a");

			let rawSentData: Uint8Array | null = null;
			const originalSend = adapterA.send.bind(adapterA);
			adapterA.send = async (data: Uint8Array) => {
				rawSentData = new Uint8Array(data);
				return originalSend(data);
			};

			const receivedMessages: string[] = [];
			channelB.on("data", (_, text) => receivedMessages.push(text()));

			await Promise.all([channelA.tryConnect(), channelB.tryConnect()]);

			const testMessage = "plaintext hello";
			await channelA.send(testMessage);
			await new Promise((r) => setTimeout(r, 50));

			// 原始数据包含类型字节（0x20 = MSG_APP_DATA）
			expect(rawSentData).not.toBeNull();
			expect(new TextDecoder().decode(rawSentData!)).toBe(testMessage);
			expect(receivedMessages).toContain(testMessage);

			channelA.disconnect();
			channelB.disconnect();
		});
	});

	describe("不受信任信道 - PAKE 配对 (trustIdentity=false)", () => {
		it("无凭证时应返回 NEEDS_PAIRING", async () => {
			const [adapterA, adapterB] = UntrustedLoopbackAdapterManager.createPair();
			adapterB.init("device-b");
			const channelA = new SConnect(adapterA);

			await channelA.init("device-a", "device-b");

			const result = await channelA.tryConnect();
			expect(result.success).toBe(false);
			if (!result.success) {
				// @ts-ignore
				expect(result.reason).toBe("NEEDS_PAIRING");
			}

			channelA.disconnect();
			adapterB.close();
		});

		it("发起方 pairInit 应触发接收方 pairRequest 事件", async () => {
			const [adapterA, adapterB] = UntrustedLoopbackAdapterManager.createPair();
			const channelA = new SConnect(adapterA, { handshakeTimeout: 10000 });
			const channelB = new SConnect(adapterB, { handshakeTimeout: 10000 });

			await channelA.init("device-a");
			await channelB.init("device-b");

			// B 监听配对请求
			const pairRequestPromise = new Promise<PairRequest>((resolve) => {
				channelB.on("pairRequest", (request) => {
					resolve(request);
				});
			});

			// A 发起配对
			const pairingA = channelA.pairInit({
				myDeviceId: "device-a",
				remoteDeviceId: "device-b",
			});

			// 等待 B 收到配对请求
			const pairRequest = await pairRequestPromise;

			expect(pairRequest.remoteDeviceId).toBe("device-a");
			expect(typeof pairRequest.inputOtherPin).toBe("function");
			expect(typeof pairRequest.reject).toBe("function");

			channelA.disconnect();
			channelB.disconnect();
		});

		it("完整配对流程：A 发起，B 输入 PIN", async () => {
			const [adapterA, adapterB] = UntrustedLoopbackAdapterManager.createPair();
			const channelA = new SConnect(adapterA, { handshakeTimeout: 10000 });
			const channelB = new SConnect(adapterB, { handshakeTimeout: 10000 });

			await channelA.init("device-a");
			await channelB.init("device-b");

			const receivedMessages: string[] = [];
			channelB.on("data", (_, text) => receivedMessages.push(text()));

			// B 监听配对请求
			const pairRequestPromise = new Promise<PairRequest>((resolve) => {
				channelB.on("pairRequest", (request) => {
					resolve(request);
				});
			});

			// A 发起配对
			const pairingA = await channelA.pairInit({
				myDeviceId: "device-a",
				remoteDeviceId: "device-b",
			});

			// 等待 B 收到配对请求
			const pairRequest = await pairRequestPromise;

			// B 输入 A 的 PIN
			pairRequest.inputOtherPin(pairingA.pin);
			const credentialBPromise = pairRequest.waitForPairing();

			// A 等待配对完成
			const credentialAPromise = pairingA.waitForPairing();

			const [credentialA, credentialB] = await Promise.all([
				credentialAPromise,
				credentialBPromise,
			]);

			expect(credentialA).toBeDefined();
			expect(credentialB).toBeDefined();
			expect(credentialA.myPublicKey).toEqual(credentialB.remotePublicKey);
			expect(credentialB.myPublicKey).toEqual(credentialA.remotePublicKey);

			// 配对后应该能收发消息
			await channelA.send("hello after pairing");
			await new Promise((r) => setTimeout(r, 100));

			expect(receivedMessages).toContain("hello after pairing");

			channelA.disconnect();
			channelB.disconnect();
		});

		it("完整配对流程2：A 发起，A 输入 PIN", async () => {
			const [adapterA, adapterB] = UntrustedLoopbackAdapterManager.createPair();
			const channelA = new SConnect(adapterA, { handshakeTimeout: 10000 });
			const channelB = new SConnect(adapterB, { handshakeTimeout: 10000 });

			await channelA.init("device-a");
			await channelB.init("device-b");

			const pinB = channelB.updatePIN();

			const receivedMessages: string[] = [];
			channelB.on("data", (_, text) => receivedMessages.push(text()));

			// B 监听配对请求
			const pairRequestPromise = new Promise<PairRequest>((resolve) => {
				channelB.on("pairRequest", (request) => {
					resolve(request);
				});
			});

			// A 发起配对
			const pairingA = await channelA.pairInit({
				myDeviceId: "device-a",
				remoteDeviceId: "device-b",
			});

			// 等待 B 收到配对请求
			const pairRequest = await pairRequestPromise;

			// A 输入 B 的 PIN（A 作为客户端）
			pairingA.inputOtherPin(pinB);

			// B 等待配对完成
			const credentialBPromise = pairRequest.waitForPairing();

			// A 也等待配对完成
			const credentialAPromise = pairingA.waitForPairing();

			const [credentialA, credentialB] = await Promise.all([
				credentialAPromise,
				credentialBPromise,
			]);

			expect(credentialA).toBeDefined();
			expect(credentialB).toBeDefined();
			expect(credentialA.myPublicKey).toEqual(credentialB.remotePublicKey);
			expect(credentialB.myPublicKey).toEqual(credentialA.remotePublicKey);

			// 配对后应该能收发消息
			await channelA.send("hello after pairing");
			await new Promise((r) => setTimeout(r, 100));

			expect(receivedMessages).toContain("hello after pairing");

			channelA.disconnect();
			channelB.disconnect();
		});

		it("B 可以拒绝配对请求", async () => {
			const [adapterA, adapterB] = UntrustedLoopbackAdapterManager.createPair();
			const channelA = new SConnect(adapterA, { pairingTimeout: 2000 });
			const channelB = new SConnect(adapterB, { pairingTimeout: 2000 });

			await channelA.init("device-a");
			await channelB.init("device-b");

			// B 监听配对请求并拒绝
			const pairRequestPromise = new Promise<PairRequest>((resolve) => {
				channelB.on("pairRequest", (request) => {
					resolve(request);
				});
			});

			// A 发起配对
			const pairingA = await channelA.pairInit({
				myDeviceId: "device-a",
				remoteDeviceId: "device-b",
			});

			// 等待 B 收到配对请求
			const pairRequest = await pairRequestPromise;

			// B 拒绝配对 - 需要捕获 rejection
			pairRequest.reject();

			// A 应该立即收到拒绝通知（不是超时）
			await expect(pairingA.waitForPairing()).rejects.toThrow();

			channelA.disconnect();
			channelB.disconnect();
		});

		it("PAKE 配对后消息应被加密 (supportNativeEncryption=false)", async () => {
			const [adapterA, adapterB] =
				UntrustedLoopbackAdapterManager.createPair(false);
			const channelA = new SConnect(adapterA, { handshakeTimeout: 10000 });
			const channelB = new SConnect(adapterB, { handshakeTimeout: 10000 });

			await channelA.init("device-a");
			await channelB.init("device-b");

			let rawSentData: Uint8Array | null = null;
			const originalSend = adapterA.send.bind(adapterA);
			adapterA.send = async (data: Uint8Array) => {
				rawSentData = new Uint8Array(data);
				return originalSend(data);
			};

			// B 监听配对请求
			const pairRequestPromise = new Promise<PairRequest>((resolve) => {
				channelB.on("pairRequest", (request) => {
					resolve(request);
				});
			});

			// A 发起配对
			const pairingA = await channelA.pairInit({
				myDeviceId: "device-a",
				remoteDeviceId: "device-b",
			});

			const pairRequest = await pairRequestPromise;
			pairRequest.inputOtherPin(pairingA.pin);
			const credentialBPromise = pairRequest.waitForPairing();
			const credentialAPromise = pairingA.waitForPairing();

			await Promise.all([credentialAPromise, credentialBPromise]);

			const testMessage = "should be encrypted";
			await channelA.send(testMessage);
			await new Promise((r) => setTimeout(r, 100));

			expect(rawSentData).not.toBeNull();
			expect(new TextDecoder().decode(rawSentData!)).not.toBe(testMessage);

			channelA.disconnect();
			channelB.disconnect();
		});

		it("supportNativeEncryption=true 时不加密", async () => {
			const [adapterA, adapterB] =
				UntrustedLoopbackAdapterManager.createPair(true);
			const channelA = new SConnect(adapterA, { handshakeTimeout: 10000 });
			const channelB = new SConnect(adapterB, { handshakeTimeout: 10000 });

			await channelA.init("device-a");
			await channelB.init("device-b");

			let rawSentData: Uint8Array | null = null;
			const originalSend = adapterA.send.bind(adapterA);
			adapterA.send = async (data: Uint8Array) => {
				rawSentData = new Uint8Array(data);
				return originalSend(data);
			};

			const receivedMessages: string[] = [];
			channelB.on("data", (_, text) => receivedMessages.push(text()));

			// B 监听配对请求
			const pairRequestPromise = new Promise<PairRequest>((resolve) => {
				channelB.on("pairRequest", (request) => {
					resolve(request);
				});
			});

			// A 发起配对
			const pairingA = await channelA.pairInit({
				myDeviceId: "device-a",
				remoteDeviceId: "device-b",
			});

			const pairRequest = await pairRequestPromise;
			pairRequest.inputOtherPin(pairingA.pin);
			const credentialBPromise = pairRequest.waitForPairing();
			const credentialAPromise = pairingA.waitForPairing();

			await Promise.all([credentialAPromise, credentialBPromise]);

			const testMessage = "native encrypted";
			await channelA.send(testMessage);
			await new Promise((r) => setTimeout(r, 100));

			expect(rawSentData).not.toBeNull();
			expect(new TextDecoder().decode(rawSentData!)).toBe(testMessage);
			expect(receivedMessages).toContain(testMessage);

			channelA.disconnect();
			channelB.disconnect();
		});
	});

	describe("不受信任信道 - Credential 重连", () => {
		it("有 Credential 时 tryConnect 应触发 connectRequest 事件", async () => {
			// 第一次配对

			const keyPairA = await generateSigningKeyPair();
			const keyPairB = await generateSigningKeyPair();

			// 第二次重连
			const [adapterA2, adapterB2] =
				UntrustedLoopbackAdapterManager.createPair();
			const channelA2 = new SConnect(adapterA2, { handshakeTimeout: 10000 });
			const channelB2 = new SConnect(adapterB2, { handshakeTimeout: 10000 });

			await channelA2.init("device-a", "device-b");
			await channelB2.init("device-b", "device-a");

			// B 监听连接请求
			const connectRequestPromise = new Promise<ConnectRequest>((resolve) => {
				channelB2.on("connectRequest", (request) => {
					resolve(request);
				});
			});

			// A 发起连接
			const resultAPromise = channelA2.tryConnect({
				createdAt: Date.now(),
				myPrivateKey: keyPairA.privateKey,
				remotePublicKey: keyPairB.publicKey,
				myPublicKey: keyPairA.publicKey,
			});

			// 等待 B 收到连接请求
			const connectRequest = await connectRequestPromise;
			expect(connectRequest.remoteDeviceId).toBe("device-a");

			channelA2.disconnect();
			channelB2.disconnect();
		});

		it("连接", async () => {
			// 第一次配对

			const keyPairA = await generateSigningKeyPair();
			const keyPairB = await generateSigningKeyPair();

			// 第二次重连
			const [adapterA2, adapterB2] =
				UntrustedLoopbackAdapterManager.createPair();
			const channelA2 = new SConnect(adapterA2, { handshakeTimeout: 10000 });
			const channelB2 = new SConnect(adapterB2, { handshakeTimeout: 10000 });

			await channelA2.init("device-a", "device-b");
			await channelB2.init("device-b", "device-a");

			// B 监听连接请求
			const connectRequestPromise = new Promise<ConnectRequest>((resolve) => {
				channelB2.on("connectRequest", (request) => {
					resolve(request);
				});
			});

			// A 发起连接
			const resultAPromise = channelA2.tryConnect({
				createdAt: Date.now(),
				myPrivateKey: keyPairA.privateKey,
				myPublicKey: keyPairA.publicKey,
				remotePublicKey: keyPairB.publicKey,
			});

			// 等待 B 收到连接请求
			const connectRequest = await connectRequestPromise;

			// B 接受连接
			const resultBPromise = connectRequest.accept({
				createdAt: Date.now(),
				myPrivateKey: keyPairB.privateKey,
				myPublicKey: keyPairB.publicKey,
				remotePublicKey: keyPairA.publicKey,
				myDeviceId: "device-b",
				remoteDeviceId: "device-a",
			});

			const [resultA, resultB] = await Promise.all([
				resultAPromise,
				resultBPromise,
			]);

			expect(resultA.success).toBe(true);
			expect(resultB.success).toBe(true);

			channelA2.disconnect();
			channelB2.disconnect();
		});

		it("B 可以拒绝连接请求", async () => {
			// 第一次配对

			const keyPairA = await generateSigningKeyPair();
			const keyPairB = await generateSigningKeyPair();

			// 第二次重连 - B 拒绝
			const [adapterA2, adapterB2] =
				UntrustedLoopbackAdapterManager.createPair();
			const channelA2 = new SConnect(adapterA2, { handshakeTimeout: 2000 });
			const channelB2 = new SConnect(adapterB2, { handshakeTimeout: 2000 });

			await channelA2.init("device-a", "device-b");
			await channelB2.init("device-b", "device-a");

			// B 监听连接请求并拒绝
			const connectRequestPromise = new Promise<ConnectRequest>((resolve) => {
				channelB2.on("connectRequest", (request) => {
					resolve(request);
				});
			});

			// A 发起连接
			const resultAPromise = channelA2.tryConnect({
				createdAt: Date.now(),
				myPrivateKey: keyPairA.privateKey,
				myPublicKey: keyPairA.publicKey,
				remotePublicKey: keyPairB.publicKey,
			});

			// 等待 B 收到连接请求
			const connectRequest = await connectRequestPromise;

			// B 拒绝连接
			connectRequest.reject();

			// A 应该收到失败结果
			const resultA = await resultAPromise;
			expect(resultA.success).toBe(false);

			channelA2.disconnect();
			channelB2.disconnect();
		});

		it("init没有记录时重连失效", async () => {
			// 第一次配对
			const keyPairA = await generateSigningKeyPair();
			const keyPairB = await generateSigningKeyPair();

			// 第二次重连 - B 自动拒绝
			const [adapterA2, adapterB2] =
				UntrustedLoopbackAdapterManager.createPair();
			const channelA2 = new SConnect(adapterA2, { handshakeTimeout: 2000 });
			const channelB2 = new SConnect(adapterB2, { handshakeTimeout: 2000 });

			await channelA2.init("device-a", "device-b");
			await channelB2.init("device-b");

			// A 发起连接
			const resultAPromise = channelA2.tryConnect({
				createdAt: Date.now(),
				myPrivateKey: keyPairA.privateKey,
				myPublicKey: keyPairA.publicKey,
				remotePublicKey: keyPairB.publicKey,
			});

			// A 应该收到失败结果
			const resultA = await resultAPromise;
			expect(resultA.success).toBe(false);

			channelA2.disconnect();
			channelB2.disconnect();
		});

		it("重连后应能收发消息", async () => {
			// 第一次配对
			const keyPairA = await generateSigningKeyPair();
			const keyPairB = await generateSigningKeyPair();

			// 第二次重连
			const [adapterA2, adapterB2] =
				UntrustedLoopbackAdapterManager.createPair();
			const channelA2 = new SConnect(adapterA2, { handshakeTimeout: 10000 });
			const channelB2 = new SConnect(adapterB2, { handshakeTimeout: 10000 });

			await channelA2.init("device-a", "device-b");
			await channelB2.init("device-b", "device-a");

			const receivedMessages: string[] = [];
			channelB2.on("data", (_, text) => receivedMessages.push(text()));

			// B 监听连接请求
			const connectRequestPromise = new Promise<ConnectRequest>((resolve) => {
				channelB2.on("connectRequest", (request) => {
					resolve(request);
				});
			});

			// A 发起连接
			const resultAPromise = channelA2.tryConnect({
				createdAt: Date.now(),
				myPrivateKey: keyPairA.privateKey,
				myPublicKey: keyPairA.publicKey,
				remotePublicKey: keyPairB.publicKey,
			});

			// B 接受连接
			const connectRequest = await connectRequestPromise;
			const resultBPromise = connectRequest.accept({
				createdAt: Date.now(),
				myPrivateKey: keyPairB.privateKey,
				myPublicKey: keyPairB.publicKey,
				remotePublicKey: keyPairA.publicKey,
				myDeviceId: "device-b",
				remoteDeviceId: "device-a",
			});

			await Promise.all([resultAPromise, resultBPromise]);

			// 重连后应该能收发消息
			await channelA2.send("hello after reconnect");
			await new Promise((r) => setTimeout(r, 100));

			expect(receivedMessages).toContain("hello after reconnect");

			channelA2.disconnect();
			channelB2.disconnect();
		});
	});

	describe("事件系统", () => {
		it("应触发 ready 和 disconnect 事件", async () => {
			const [adapterA, adapterB] = LoopbackAdapterManager.createPair();
			const channelA = new SConnect(adapterA);
			const channelB = new SConnect(adapterB);

			await channelA.init("device-a", "device-b");
			await channelB.init("device-b", "device-a");

			// @ts-ignore
			const readyPromise = waitForEvent(channelA, "ready");

			await Promise.all([channelA.tryConnect(), channelB.tryConnect()]);

			await readyPromise;

			// @ts-ignore
			const disconnectPromise = waitForEvent(channelB, "disconnect");
			channelA.disconnect();
			await disconnectPromise;

			channelB.disconnect();
		});
	});

	describe("二进制数据传输", () => {
		it("应支持发送和接收二进制数据", async () => {
			const [adapterA, adapterB] = LoopbackAdapterManager.createPair();
			const channelA = new SConnect(adapterA);
			const channelB = new SConnect(adapterB);

			await channelA.init("device-a", "device-b");
			await channelB.init("device-b", "device-a");

			const receivedData: ArrayBuffer[] = [];
			channelB.on("data", (data) => receivedData.push(data));

			await Promise.all([channelA.tryConnect(), channelB.tryConnect()]);

			const testData = new Uint8Array([1, 2, 3, 4, 5]);
			await channelA.sendBinary(testData);
			await new Promise((r) => setTimeout(r, 100));

			expect(receivedData.length).toBe(1);
			expect(new Uint8Array(receivedData[0])).toEqual(testData);

			channelA.disconnect();
			channelB.disconnect();
		});
	});

	describe("频率限制", () => {
		it("应限制配对请求频率", async () => {
			const [adapterA, adapterB] = UntrustedLoopbackAdapterManager.createPair();
			const channelA = new SConnect(adapterA, { pairInterval: 1000 });
			const channelB = new SConnect(adapterB, { pairInterval: 1000 });

			await channelA.init("device-a");
			await channelB.init("device-b");

			// B 监听配对请求
			let pairRequestCount = 0;
			channelB.on("pairRequest", (request) => {
				if (pairRequestCount === 0) {
					request.reject();
				}
				pairRequestCount++;
			});

			let errorCount = 0;

			// A 连续发起多个配对请求
			for (let i = 0; i < 5; i++) {
				try {
					const p = await channelA.pairInit({
						myDeviceId: "device-a",
						remoteDeviceId: "device-b",
					});
					await p.waitForPairing();
				} catch (e) {
					errorCount++;
				}
			}

			// 由于频率限制，B 应该只收到有限的配对请求
			expect(pairRequestCount).toBeLessThan(5);
			expect(errorCount).toBe(5);

			channelA.disconnect();
			channelB.disconnect();
		});

		it("应限制连接请求频率", async () => {
			const [adapterA1, adapterB1] =
				UntrustedLoopbackAdapterManager.createPair();
			const channelA1 = new SConnect(adapterA1, { handshakeTimeout: 10000 });
			const channelB1 = new SConnect(adapterB1, { handshakeTimeout: 10000 });

			await channelA1.init("device-a");
			await channelB1.init("device-b");

			// B 监听配对请求
			const pairRequestPromise = new Promise<PairRequest>((resolve) => {
				channelB1.on("pairRequest", (request) => {
					resolve(request);
				});
			});

			// A 发起配对
			const pairingA = await channelA1.pairInit({
				myDeviceId: "device-a",
				remoteDeviceId: "device-b",
			});

			const pairRequest = await pairRequestPromise;
			pairRequest.inputOtherPin(pairingA.pin);
			const credentialBPromise = pairRequest.waitForPairing();
			const credentialAPromise = pairingA.waitForPairing();

			const [credentialA] = await Promise.all([
				credentialAPromise,
				credentialBPromise,
			]);

			channelA1.disconnect();
			channelB1.disconnect();

			const [adapterA2, adapterB2] =
				UntrustedLoopbackAdapterManager.createPair();
			const channelA = new SConnect(adapterA2, { connectInterval: 100 });
			const channelB = new SConnect(adapterB2, { connectInterval: 100 });

			await channelA.init("device-a", "device-b");
			await channelB.init("device-b", "device-a");

			// B 监听连接请求
			let connectRequestCount = 0;
			channelB.on("connectRequest", (request) => {
				if (connectRequestCount === 0) {
					request.reject();
				}
				connectRequestCount++;
			});

			// A 连续发起多个连接请求
			for (let i = 0; i < 20; i++) {
				const r = await channelA.tryConnect(credentialA);
				// 本来只拒绝第一次连接请求，后续的应该被频率限制拒绝
				expect(r.success).toBeFalsy();
			}

			// 由于频率限制，B 应该只收到有限的连接请求
			expect(connectRequestCount).toBeLessThan(20);

			channelA.disconnect();
			channelB.disconnect();
		});
	});
});

describe("密码学验证", () => {
	it("dh交换", async () => {
		const keyPairA = await generateKeyPair();
		const keyPairB = await generateKeyPair();
		expect(await dh(keyPairA.privateKey, keyPairB.publicKey)).toEqual(
			await dh(keyPairB.privateKey, keyPairA.publicKey),
		);
	});
	it("盲签名", async () => {
		const keyPair = await generateKeyPair();
		const pin = "1234";
		const blinded = blind(pin, keyPair.publicKey);
		const deblinded = deBlind(blinded, pin);
		expect(deblinded).toEqual(keyPair.publicKey);
	});
	it("签名验证", async () => {
		const keyPair = await generateSigningKeyPair();
		const data = new TextEncoder().encode("test data");
		const signature = await sigh(keyPair.privateKey, data);
		const isValid = await verifySignature(keyPair.publicKey, data, signature);
		expect(isValid).toBe(true);
	});

	describe("AES-GCM 加密解密", () => {
		it("AES-GCM 加密解密", async () => {
			const key = crypto.getRandomValues(new Uint8Array(32));
			const c = new cipher(key, key);

			const plaintext = new TextEncoder().encode("hello world");
			const encrypted = await c.encrypt(plaintext);
			const decrypted = await c.decrypt(encrypted);

			expect(decrypted).toEqual(plaintext);
			expect(encrypted).not.toEqual(plaintext);
		});

		it("AES-GCM 加密输出包含 IV", async () => {
			const key = crypto.getRandomValues(new Uint8Array(32));
			const c = new cipher(key, key);

			const plaintext = new TextEncoder().encode("test");
			const encrypted = await c.encrypt(plaintext);

			// IV (12) + ciphertext (16 minimum for AES-GCM)
			expect(encrypted.length).toBeGreaterThanOrEqual(28);
		});

		it("AES-GCM 不同密钥解密失败", async () => {
			const key1 = crypto.getRandomValues(new Uint8Array(32));
			const key2 = crypto.getRandomValues(new Uint8Array(32));
			const c1 = new cipher(key1, key1);
			const c2 = new cipher(key2, key2);

			const plaintext = new TextEncoder().encode("secret");
			const encrypted = await c1.encrypt(plaintext);

			await expect(c2.decrypt(encrypted)).rejects.toThrow();
		});

		it("AES-GCM 二进制数据加密解密", async () => {
			const key = crypto.getRandomValues(new Uint8Array(32));
			const c = new cipher(key, key);

			const binaryData = new Uint8Array([0, 1, 2, 255, 254, 253]);
			const encrypted = await c.encrypt(binaryData);
			const decrypted = await c.decrypt(encrypted);

			expect(decrypted).toEqual(binaryData);
		});

		it("AES-GCM sendKey 和 receiveKey 不同", async () => {
			const sendKey = crypto.getRandomValues(new Uint8Array(32));
			const receiveKey = crypto.getRandomValues(new Uint8Array(32));
			const c = new cipher(sendKey, receiveKey);

			// 使用 sendKey 加密，receiveKey 解密会失败（因为密钥不同）
			const plaintext = new TextEncoder().encode("test");
			const encrypted = await c.encrypt(plaintext);

			// 创建另一个 cipher，交换 sendKey 和 receiveKey
			const c2 = new cipher(receiveKey, sendKey);
			const decrypted = await c2.decrypt(encrypted);

			expect(decrypted).toEqual(plaintext);
		});
	});
});
