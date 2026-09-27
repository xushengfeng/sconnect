/**
 * 对抗性安全回归测试
 *
 * 对应 SECURITY_PLAN.md 中的 C1/C2/C3：
 * - C1 反射攻击：不知 PIN 的攻击者原样回显密钥确认 MAC，配对必须失败
 * - C2 空 PIN：接收方 PIN 未生成时被 MSG_USE_YOUR_PIN 强制生效，配对必须失败
 * - C3 中间人替换身份公钥：双方配对必须失败，且双向确认 MAC 必须不同
 *
 * 攻击者使用原始消息（不走 SConnect），模拟真实的主动攻击者。
 */
import { describe, expect, it } from "vitest";
import {
	SConnect,
	dh,
	generateKeyPair,
	generateSigningKeyPair,
	hashToCurvePoint,
} from "./sconnect";
import { UntrustedLoopbackAdapterManager } from "./loopback_adapter";
import type { ConnectRequest, PairRequest } from "./sconnect_type";

const MSG_PAIR_REQUEST = 1;
const MSG_USE_YOUR_PIN = 2;
const MSG_CONNECT_REQUEST = 3;
const MSG_CONNECT_ACCEPT = 4;
const MSG_SPAKE_DATA = 11;
const MSG_BLIND_PUBLIC_KEY = 12;
const MSG_CONNECT_PUBLIC_KEY = 13;
const MSG_CONNECT_MAC_VER = 14;
const MSG_SIGNING_PUBLIC_KEY = 15;

/** 原始攻击者/中间人：单一分发器 + 队列，避免消息竞态丢失 */
function rawPeer(adapter: {
	send: (d: Uint8Array) => Promise<void>;
	onMessage: (h: (d: Uint8Array) => void) => void;
}) {
	const queue: Uint8Array[] = [];
	const pending = new Map<number, (d: Uint8Array) => void>();
	const seenTypes: number[] = [];
	adapter.onMessage((data) => {
		seenTypes.push(data[0]);
		const r = pending.get(data[0]);
		if (r) {
			pending.delete(data[0]);
			r(data.subarray(1));
		} else {
			queue.push(data);
		}
	});
	const wait = (type: number) =>
		new Promise<Uint8Array>((resolve) => {
			const i = queue.findIndex((m) => m[0] === type);
			if (i !== -1) resolve(queue.splice(i, 1)[0].subarray(1));
			else pending.set(type, resolve);
		});
	const send = (type: number, payload?: Uint8Array) =>
		adapter.send(new Uint8Array([type, ...(payload ?? new Uint8Array(0))]));
	return { wait, send, seenTypes };
}

describe("安全回归：配对协议对抗性测试", () => {
	it("C1：反射攻击（不知 PIN，回显 MAC）必须配对失败", async () => {
		const manager = new UntrustedLoopbackAdapterManager();
		const victimAdapter = manager.newAdapter(false);
		const attackerAdapter = manager.newAdapter(false);
		await victimAdapter.init("victim");
		await attackerAdapter.init("attacker");
		manager.connect("victim", "attacker");

		const victim = new SConnect(victimAdapter, { handshakeTimeout: 5000 });
		await victim.init("victim", "attacker");

		const atk = rawPeer(attackerAdapter);
		(async () => {
			await atk.wait(MSG_PAIR_REQUEST);
			// 让受害者使用它自己的 PIN（攻击者从不知道该 PIN）
			await atk.send(MSG_USE_YOUR_PIN);
			await atk.wait(MSG_BLIND_PUBLIC_KEY);
			// 发送任意 32 字节（攻击者不知道对应私钥）
			await atk.send(MSG_BLIND_PUBLIC_KEY, new Uint8Array(32).fill(9));
			// 协议顺序：先交换身份公钥，再做密钥确认
			await atk.wait(MSG_SIGNING_PUBLIC_KEY);
			// 冒充身份：塞入攻击者自己的"公钥"
			await atk.send(MSG_SIGNING_PUBLIC_KEY, new Uint8Array(32).fill(7));
			const confirmMac = await atk.wait(MSG_SPAKE_DATA);
			// 核心攻击：把受害者的密钥确认 MAC 原样反射回去
			await atk.send(MSG_SPAKE_DATA, confirmMac);
		})();

		const pairing = await victim.pairInit({
			myDeviceId: "victim",
			remoteDeviceId: "attacker",
		});
		// 攻击者全程未知 pairing.pin
		await expect(pairing.waitForPairing()).rejects.toMatchObject({
			code: "PAIRING_FAILED",
		});
	});

	it("C2：接收方 PIN 为空时，攻击者用空 PIN 完成 SPEKE 必须失败", async () => {
		const manager = new UntrustedLoopbackAdapterManager();
		const victimAdapter = manager.newAdapter(false);
		const attackerAdapter = manager.newAdapter(false);
		await victimAdapter.init("victim");
		await attackerAdapter.init("attacker");
		manager.connect("victim", "attacker");

		const victim = new SConnect(victimAdapter, { handshakeTimeout: 5000 });
		await victim.init("victim", "attacker");

		const pairRequestPromise = new Promise<PairRequest>((resolve) => {
			victim.on("pairRequest", (req) => resolve(req));
		});

		const atk = rawPeer(attackerAdapter);
		// 攻击者完整实现 SPEKE，使用 PIN = ""（接收方默认未生成 PIN）
		(async () => {
			await atk.send(MSG_PAIR_REQUEST, new TextEncoder().encode("attacker"));
			// 让受害者使用其 this.PIN（默认为空字符串）
			await atk.send(MSG_USE_YOUR_PIN);

			const kp = await generateKeyPair();
			const pinPoint = await hashToCurvePoint("");
			const myBlinded = await dh(kp.privateKey, pinPoint);
			const otherBlinded = await atk.wait(MSG_BLIND_PUBLIC_KEY);
			await atk.send(MSG_BLIND_PUBLIC_KEY, myBlinded);
			// 即便攻击者能算出真正的共享秘密（PIN="" 可预知），也不得通过
			await dh(kp.privateKey, otherBlinded);
			await atk.wait(MSG_SIGNING_PUBLIC_KEY);
			await atk.send(MSG_SIGNING_PUBLIC_KEY, new Uint8Array(32).fill(7));
			const victimMac = await atk.wait(MSG_SPAKE_DATA);
			await atk.send(MSG_SPAKE_DATA, victimMac);
		})();

		const req = await pairRequestPromise;
		// 模拟应用：收到请求即调用 waitForPairing，用户尚未输入 PIN
		await expect(req.waitForPairing()).rejects.toMatchObject({
			code: "PIN_INVALID",
		});
	});

	it("C3：中间人替换身份公钥必须失败，且双向确认 MAC 必须不同", async () => {
		const manager = new UntrustedLoopbackAdapterManager();
		const adA = manager.newAdapter(false);
		const adB = manager.newAdapter(false);
		const adIn = manager.newAdapter(false);
		const adOut = manager.newAdapter(false);
		await adA.init("device-a");
		await adB.init("device-b");
		await adIn.init("mitm-in");
		await adOut.init("mitm-out");

		// 布线：A <-> mitm-in <-> mitm-out <-> B，并冻结布线
		// （防止 pairInit 内部 connect() 触发 manager.connect 重排）
		adA.peer = adIn;
		adIn.peer = adA;
		adB.peer = adOut;
		adOut.peer = adB;
		Object.assign(manager, { connect: () => {} });

		// 中间人：转发一切，但替换双向 MSG_SIGNING_PUBLIC_KEY；
		// 同时记录双向 MSG_SPAKE_DATA 用于方向性断言
		const fakeKeyForA = new Uint8Array(32).fill(0xaa);
		const fakeKeyForB = new Uint8Array(32).fill(0xbb);
		const macsSeen: Uint8Array[] = [];
		const forward = (
			to: typeof adIn,
			fakeKey: Uint8Array,
		): ((data: Uint8Array) => void) => {
			return (data: Uint8Array) => {
				if (data[0] === MSG_SIGNING_PUBLIC_KEY) {
					void to.send(new Uint8Array([MSG_SIGNING_PUBLIC_KEY, ...fakeKey]));
				} else {
					if (data[0] === MSG_SPAKE_DATA) {
						macsSeen.push(data.subarray(1));
					}
					void to.send(data);
				}
			};
		};
		adIn.onMessage(forward(adOut, fakeKeyForB));
		adOut.onMessage(forward(adIn, fakeKeyForA));

		const channelA = new SConnect(adA, { handshakeTimeout: 5000 });
		const channelB = new SConnect(adB, { handshakeTimeout: 5000 });
		await channelA.init("device-a", "device-b");
		await channelB.init("device-b", "device-a");

		const pairRequestPromise = new Promise<PairRequest>((resolve) => {
			channelB.on("pairRequest", (req) => resolve(req));
		});

		const pairingA = await channelA.pairInit({
			myDeviceId: "device-a",
			remoteDeviceId: "device-b",
		});
		const pairRequest = await pairRequestPromise;

		// 正常用户流程：B 输入 A 显示的 PIN
		pairRequest.inputOtherPin(pairingA.pin);
		const aDone = pairingA.waitForPairing();
		const bDone = pairRequest.waitForPairing();

		const results = await Promise.allSettled([aDone, bDone]);
		// 双方都必须失败：transcript 身份公钥不同导致 MAC 校验必然不过
		expect(results[0].status).toBe("rejected");
		expect(results[1].status).toBe("rejected");

		// C1 结构断言：双方的确认 MAC 输入了不同角色标签，值必须不同
		// （修复前两侧 MAC 逐字节相同，反射才得以成立）
		expect(macsSeen.length).toBe(2);
		expect(Buffer.from(macsSeen[0]).equals(Buffer.from(macsSeen[1]))).toBe(
			false,
		);
	});
});

describe("安全回归：失败原因与状态机 (H2/M4)", () => {
	it("H2：签名被篡改必须返回 AUTH_FAILED 而非 NEEDS_PAIRING", async () => {
		const manager = new UntrustedLoopbackAdapterManager();
		const victimAdapter = manager.newAdapter(false);
		const attackerAdapter = manager.newAdapter(false);
		await victimAdapter.init("device-a");
		await attackerAdapter.init("attacker");
		manager.connect("device-a", "attacker");

		const victim = new SConnect(victimAdapter, { handshakeTimeout: 2000 });
		await victim.init("device-a", "attacker");

		const atk = rawPeer(attackerAdapter);
		(async () => {
			await atk.wait(MSG_CONNECT_REQUEST);
			await atk.send(MSG_CONNECT_ACCEPT, new Uint8Array([1]));
			await atk.wait(MSG_CONNECT_PUBLIC_KEY);
			// 回一个长度合法（32+64）但签名无效的公钥包
			await atk.send(MSG_CONNECT_PUBLIC_KEY, new Uint8Array(96).fill(6));
		})();

		const my = await generateSigningKeyPair();
		const result = await victim.tryConnect({
			createdAt: Date.now(),
			myPrivateKey: my.privateKey,
			myPublicKey: my.publicKey,
			remotePublicKey: new Uint8Array(32).fill(5),
		});
		// 必须是显式的验证失败，应用层需要据此警示用户而非静默重新配对
		expect(result).toMatchObject({ success: false, reason: "AUTH_FAILED" });
	});

	it("H2：MAC 被篡改必须返回 AUTH_FAILED（双向）", async () => {
		const manager = new UntrustedLoopbackAdapterManager();
		const adA = manager.newAdapter(false);
		const adB = manager.newAdapter(false);
		const adIn = manager.newAdapter(false);
		const adOut = manager.newAdapter(false);
		await adA.init("device-a");
		await adB.init("device-b");
		await adIn.init("mitm-in");
		await adOut.init("mitm-out");
		adA.peer = adIn;
		adIn.peer = adA;
		adB.peer = adOut;
		adOut.peer = adB;
		Object.assign(manager, { connect: () => {} });

		// 中间人：转发一切，但翻转 MSG_CONNECT_MAC_VER 的末字节
		const corrupt = (data: Uint8Array): Uint8Array => {
			if (data[0] !== MSG_CONNECT_MAC_VER) return data;
			const bad = new Uint8Array(data);
			bad[bad.length - 1] ^= 0xff;
			return bad;
		};
		adIn.onMessage((data) => void adOut.send(corrupt(data)));
		adOut.onMessage((data) => void adIn.send(corrupt(data)));

		const channelA = new SConnect(adA, { handshakeTimeout: 2000 });
		const channelB = new SConnect(adB, { handshakeTimeout: 2000 });
		await channelA.init("device-a", "device-b");
		await channelB.init("device-b", "device-a");

		const connectRequestPromise = new Promise<ConnectRequest>((resolve) => {
			channelB.on("connectRequest", (req) => resolve(req));
		});

		const keyPairA = await generateSigningKeyPair();
		const keyPairB = await generateSigningKeyPair();

		const resultAPromise = channelA.tryConnect({
			createdAt: Date.now(),
			myPrivateKey: keyPairA.privateKey,
			myPublicKey: keyPairA.publicKey,
			remotePublicKey: keyPairB.publicKey,
		});
		const connectRequest = await connectRequestPromise;
		const resultBPromise = connectRequest.acceptWithCre({
			createdAt: Date.now(),
			myPrivateKey: keyPairB.privateKey,
			myPublicKey: keyPairB.publicKey,
			remotePublicKey: keyPairA.publicKey,
		});

		const [resultA, resultB] = await Promise.all([
			resultAPromise,
			resultBPromise,
		]);
		expect(resultA).toMatchObject({ success: false, reason: "AUTH_FAILED" });
		expect(resultB).toMatchObject({ success: false, reason: "AUTH_FAILED" });
	});

	it("M4：未知类型垃圾不得破坏合法配对，握手中的配对请求不得派发", async () => {
		const manager = new UntrustedLoopbackAdapterManager();
		const adA = manager.newAdapter(false);
		const adB = manager.newAdapter(false);
		const adIn = manager.newAdapter(false);
		const adOut = manager.newAdapter(false);
		await adA.init("device-a");
		await adB.init("device-b");
		await adIn.init("mitm-in");
		await adOut.init("mitm-out");
		adA.peer = adIn;
		adIn.peer = adA;
		adB.peer = adOut;
		adOut.peer = adB;
		Object.assign(manager, { connect: () => {} });

		// 中间人：转发一切，同时持续注入未知类型垃圾；
		// 在握手开始（见到 MSG_BLIND_PUBLIC_KEY）后向 B 注入 MSG_PAIR_REQUEST
		const junk = () => {
			void adOut.send(new Uint8Array([99, 1, 2]));
			void adIn.send(new Uint8Array([200, 3]));
			void adOut.send(new Uint8Array([255]));
			void adIn.send(new Uint8Array([77, 77]));
		};
		adIn.onMessage((data) => {
			junk();
			if (data[0] === MSG_BLIND_PUBLIC_KEY) {
				void adOut.send(
					new Uint8Array([MSG_PAIR_REQUEST, ...new TextEncoder().encode("fake")]),
				);
			}
			void adOut.send(data);
		});
		adOut.onMessage((data) => {
			junk();
			void adIn.send(data);
		});

		const channelA = new SConnect(adA, { handshakeTimeout: 5000 });
		const channelB = new SConnect(adB, { handshakeTimeout: 5000 });
		await channelA.init("device-a", "device-b");
		await channelB.init("device-b", "device-a");

		let pairRequestCount = 0;
		const pairRequestPromise = new Promise<PairRequest>((resolve) => {
			channelB.on("pairRequest", (req) => {
				pairRequestCount++;
				resolve(req);
			});
		});

		const pairingA = await channelA.pairInit({
			myDeviceId: "device-a",
			remoteDeviceId: "device-b",
		});
		const pairRequest = await pairRequestPromise;
		pairRequest.inputOtherPin(pairingA.pin);

		const [credentialA, credentialB] = await Promise.all([
			pairingA.waitForPairing(),
			pairRequest.waitForPairing(),
		]);

		// 垃圾注入下合法配对仍须成功，且身份互相正确
		expect(credentialA.myPublicKey).toEqual(credentialB.remotePublicKey);
		expect(credentialB.myPublicKey).toEqual(credentialA.remotePublicKey);
		// 握手期间注入的 MSG_PAIR_REQUEST 不得再派发第二个事件
		expect(pairRequestCount).toBe(1);
	});

	it("M4：跨会话残留消息必须被清理，不得被新握手消费", async () => {
		const manager = new UntrustedLoopbackAdapterManager();
		const victimAdapter = manager.newAdapter(false);
		const attackerAdapter = manager.newAdapter(false);
		await victimAdapter.init("device-a");
		await attackerAdapter.init("attacker");
		manager.connect("device-a", "attacker");

		const victim = new SConnect(victimAdapter, { handshakeTimeout: 500 });
		await victim.init("device-a", "attacker");

		const atk = rawPeer(attackerAdapter);
		// 注入"上一会话残留"的连接接受消息
		await atk.send(MSG_CONNECT_ACCEPT, new Uint8Array([1]));
		await new Promise((r) => setTimeout(r, 20));

		const my = await generateSigningKeyPair();
		const result = await victim.tryConnect({
			createdAt: Date.now(),
			myPrivateKey: my.privateKey,
			myPublicKey: my.publicKey,
			remotePublicKey: new Uint8Array(32).fill(5),
		});

		expect(result.success).toBe(false);
		// A 发出了新的连接请求……
		expect(atk.seenTypes).toContain(MSG_CONNECT_REQUEST);
		// ……但没有消费残留的 ACCEPT 去发送公钥（否则说明陈旧消息被误用）
		expect(atk.seenTypes).not.toContain(MSG_CONNECT_PUBLIC_KEY);
	});
});
