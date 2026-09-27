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
	hashToCurvePoint,
} from "./sconnect";
import { UntrustedLoopbackAdapterManager } from "./loopback_adapter";
import type { PairRequest } from "./sconnect_type";

const MSG_PAIR_REQUEST = 1;
const MSG_USE_YOUR_PIN = 2;
const MSG_SPAKE_DATA = 11;
const MSG_BLIND_PUBLIC_KEY = 12;
const MSG_SIGNING_PUBLIC_KEY = 15;

/** 原始攻击者/中间人：单一分发器 + 队列，避免消息竞态丢失 */
function rawPeer(adapter: {
	send: (d: Uint8Array) => Promise<void>;
	onMessage: (h: (d: Uint8Array) => void) => void;
}) {
	const queue: Uint8Array[] = [];
	const pending = new Map<number, (d: Uint8Array) => void>();
	adapter.onMessage((data) => {
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
	return { wait, send };
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
