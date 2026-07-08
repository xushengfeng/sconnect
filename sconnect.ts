import type {
	ChannelOptions,
	ChannelState,
	ConnectRequest,
	ConnectResult,
	Credential,
	CredentialPrivateInfo,
	CredentialPublicInfo,
	HandshakeType,
	PairRequest,
	SecureChannel,
	SecureChannelEvents,
	SignalingAdapter,
} from "./sconnect_type";
import {
	createNoise,
	initialiseNoise,
	sendNoise,
	recvNoise,
	destroyNoise,
	createCipher,
	type NoiseState,
} from "./noise_utils";

interface KeyPair {
	publicKey: Uint8Array;
	privateKey: Uint8Array;
}

// 协议消息类型
const MSG_PAIR_REQUEST = 0x01;
const MSG_USE_YOUR_PIN = 0x02; // 通知对方使用自己的 PIN
const MSG_PAIR_REJECT = 0x07; // 拒绝配对请求
const MSG_CONNECT_REQUEST = 0x03;
const MSG_CONNECT_ACCEPT = 0x04;
const MSG_CONNECT_REJECT = 0x05;
const MSG_ERROR = 0x06;
const MSG_NOISE_DATA = 0x10;
const MSG_SPAKE_DATA = 0x11;
const MSG_APP_DATA = 0x20;
const MSG_BLIND_PUBLIC_KEY = 0x12;

// 错误类
class SConnectError extends Error {
	code: ErrorCode;
	recoverable: boolean;

	constructor(code: ErrorCode, message: string, recoverable = true) {
		super(message);
		this.name = "SConnectError";
		this.code = code;
		this.recoverable = recoverable;
	}
}

type ErrorCode =
	// 配对错误
	| "PIN_INVALID"
	| "PIN_MISMATCH"
	| "PAKE_FAILED"
	| "PAIRING_FAILED"
	// 连接错误
	| "TIMEOUT"
	| "ADAPTER_ERROR"
	| "PEER_DISCONNECTED"
	// 验证错误
	| "CREDENTIAL_INVALID"
	| "CREDENTIAL_EXPIRED"
	| "IK_HANDSHAKE_FAILED"
	// 状态错误
	| "NOT_INITIALIZED"
	| "ALREADY_CONNECTING"
	| "CHANNEL_NOT_READY"
	| "REMOTE_ID_UNKNOWN"
	// 对端错误
	| "UNEXPECTED_MESSAGE"
	| "NOT_CONNECTED"
	| "ALREADY_CONNECTED"
	// 致命错误
	| "ADAPTER_INIT_FAILED"
	| "CRYPTO_UNAVAILABLE";

class Limiter {
	private lastTime = 0;
	constructor(private interval: number) {}
	canExecute(): boolean {
		const now = Date.now();
		if (now - this.lastTime >= this.interval) {
			this.lastTime = now;
			return true;
		}
		return false;
	}
	cleanup() {
		this.lastTime = 0;
	}
}

export class SConnect implements SecureChannel {
	private signalAdapter: SignalingAdapter;
	private options: Required<ChannelOptions>;
	private remoteId = "";
	private noise: NoiseState | null = null;
	private sendCipher: ReturnType<typeof createCipher> | null = null;
	private receiveCipher: ReturnType<typeof createCipher> | null = null;
	private PIN = "";
	private eventHandlers: Map<string, Set<(...args: unknown[]) => void>> =
		new Map();

	// 状态机
	private state: ChannelState = "Idle";
	private handshakeType: HandshakeType = null;
	private handshakeMessageHandler:
		| ((type: number, payload: Uint8Array) => void)
		| null = null;
	private handshakeMessageQueue: { type: number; payload: Uint8Array }[] = [];
	private typeMessageQueue: { type: number; payload: Uint8Array }[] = [];
	private typeMessageResolvers: Map<
		number,
		{ resolve: (data: Uint8Array) => void; reject: (err: Error) => void }
	> = new Map();

	// 设备身份
	private myDeviceId = "";
	private myKeyPair: KeyPair | null = null;

	// 计时器管理
	private activeTimers: Set<ReturnType<typeof setTimeout>> = new Set();

	private pairLimiter: Limiter;
	private connectLimiter: Limiter;

	private textDecoder = new TextDecoder();

	constructor(signalAdapter: SignalingAdapter, options?: ChannelOptions) {
		this.signalAdapter = signalAdapter;
		this.options = {
			connectTimeout: options?.connectTimeout ?? 30000,
			pairingTimeout: options?.pairingTimeout ?? 60000,
			handshakeTimeout: options?.handshakeTimeout ?? 30000,
			maxPinAttempts: options?.maxPinAttempts ?? 5,
			pairInterval: options?.pairInterval ?? 1000,
			connectInterval: options?.connectInterval ?? 20,
		};

		this.pairLimiter = new Limiter(this.options.pairInterval);
		this.connectLimiter = new Limiter(this.options.connectInterval);

		this.signalAdapter.onMessage((data) => this.handleRawMessage(data));
		this.signalAdapter.onClose(() => this.handleDisconnect());
		this.signalAdapter.onError((err) =>
			this.emit("error", this.wrapError(err)),
		);
	}

	// ================= 初始化 =================

	async init(myDeviceId: string, remoteId?: string) {
		if (this.state !== "Idle") {
			throw new SConnectError("NOT_INITIALIZED", "Already initialized");
		}

		this.myDeviceId = myDeviceId;
		if (remoteId) {
			this.remoteId = remoteId;
		}
		await this.signalAdapter.init(myDeviceId);

		this.myKeyPair = await this.generateKeyPair();

		this.setState("Ready");
	}

	// ================= 连接 =================

	async tryConnect(credential?: CredentialPrivateInfo): Promise<ConnectResult> {
		if (this.state !== "Ready") {
			throw new SConnectError(
				"CHANNEL_NOT_READY",
				`Cannot connect in ${this.state} state`,
			);
		}

		if (!this.remoteId) {
			throw new SConnectError(
				"REMOTE_ID_UNKNOWN",
				"Remote ID is not known. Try pairing first.",
			);
		}

		try {
			await this.signalAdapter.connect(this.remoteId);

			if (this.signalAdapter.trustIdentity) {
				this.setState("Connected");
				this.emit("ready");
				return { success: true, credential: this.buildCredential(credential) };
			}

			if (
				credential &&
				"myPrivateKey" in credential &&
				credential.myPrivateKey
			) {
				this.setState("Handshaking", "connect-request");
				return await this.sendConnectRequest(credential);
			}

			return { success: false, reason: "NEEDS_PAIRING" };
		} catch (error) {
			this.setState("Ready");
			this.emit("error", this.wrapError(error));
			return { success: false };
		}
	}

	private handleConnectRequest(payload: Uint8Array): void {
		const senderIdLength = new DataView(
			payload.buffer,
			payload.byteOffset,
		).getUint16(0);
		const senderId = new TextDecoder().decode(
			payload.subarray(2, 2 + senderIdLength),
		);

		if (senderId !== this.remoteId) {
			this.sendHandshakeMessage(MSG_CONNECT_REJECT, new Uint8Array(0)).catch(
				() => {},
			);
			return;
		}

		if (!this.connectLimiter.canExecute()) {
			// todo 提示被频繁占用
			this.signalAdapter
				.send(new Uint8Array([MSG_CONNECT_REJECT]))
				.catch(() => {});
			return;
		}

		const request: ConnectRequest = {
			remoteDeviceId: senderId,
			accept: (credential: Credential): Promise<ConnectResult> => {
				this.setState("Handshaking", "connect-response");
				this.sendHandshakeMessage(MSG_CONNECT_ACCEPT, new Uint8Array(0)).catch(
					() => {},
				);
				return this.performIKResponder(credential);
			},
			reject: () => {
				this.sendHandshakeMessage(MSG_CONNECT_REJECT, new Uint8Array(0)).catch(
					() => {},
				);
			},
		};

		this.emit("connectRequest", request);
	}

	// ================= 配对 =================

	updatePIN(): string {
		this.PIN = this.generatePin();
		return this.PIN;
	}

	async pairInit(credential: CredentialPublicInfo): Promise<{
		pin: string;
		inputOtherPin: (pin: string) => void;
		waitForPairing: () => Promise<Credential>;
	}> {
		if (this.state !== "Ready") {
			throw new SConnectError(
				"CHANNEL_NOT_READY",
				`Cannot pair in ${this.state} state`,
			);
		}

		const pin = this.PIN || this.updatePIN();

		await this.signalAdapter.connect(credential.remoteDeviceId);

		const otherPin = Promise.withResolvers<string>();

		const inputOtherPin = (remotePin: string) => {
			if (!this.validatePin(remotePin)) {
				otherPin.reject(
					new SConnectError("PIN_INVALID", "PIN must be 6 digits"),
				);
				throw new SConnectError("PIN_INVALID", "PIN must be 6 digits");
			}

			otherPin.resolve(remotePin);
		};

		const waitForPairing = Promise.withResolvers<Credential>();

		// 发送配对请求
		this.sendTypeMessage(
			MSG_PAIR_REQUEST,
			new TextEncoder().encode(this.myDeviceId),
		).catch(() => {});

		this.getTypeMessage(MSG_PAIR_REJECT).then(() => {
			waitForPairing.reject(
				new SConnectError("PAIRING_FAILED", "Pairing request was rejected"),
			);
		});

		return {
			pin,
			inputOtherPin,
			waitForPairing: () => {
				this.genWaitForPairing({
					remoteDeviceId: credential.remoteDeviceId,
					otherPin: otherPin.promise,
					PIN: pin,
				})
					.then(waitForPairing.resolve)
					.catch(waitForPairing.reject);
				return waitForPairing.promise;
			},
		};
	}

	private async genWaitForPairing(op: {
		remoteDeviceId: string;
		otherPin: Promise<string>;
		PIN: string;
	}): Promise<Credential> {
		const keyPair = await generateKeyPair();
		const finalPin = await Promise.race([
			(async () => {
				const pin = await op.otherPin;
				await this.sendTypeMessage(MSG_USE_YOUR_PIN);
				return pin;
			})(),
			(async () => {
				await this.getTypeMessage(MSG_USE_YOUR_PIN);
				return op.PIN;
			})(),
		]);
		const bindPublicKey = blind(finalPin, keyPair.publicKey);
		await this.sendTypeMessage(MSG_BLIND_PUBLIC_KEY, bindPublicKey);
		const otherBindPublicKey = await this.getTypeMessage(MSG_BLIND_PUBLIC_KEY);
		if (otherBindPublicKey === undefined) {
			throw new SConnectError(
				"PAIRING_FAILED",
				"Failed to receive blinded public key from peer",
			);
		}
		const otherPublicKey = deBlind(otherBindPublicKey, finalPin);
		const s = await dh(keyPair.privateKey, otherPublicKey);

		const info = buildPairingInfo(
			finalPin,
			this.myDeviceId,
			op.remoteDeviceId,
			keyPair.publicKey,
			otherPublicKey,
		);
		const derivedKey = await derive(
			s,
			info,
			new TextEncoder().encode(finalPin),
		);
		const myMac = await mac(derivedKey, info);
		await this.sendTypeMessage(MSG_SPAKE_DATA, myMac);
		const otherMac = await this.getTypeMessage(MSG_SPAKE_DATA);

		const otherInfo = buildPairingInfo(
			finalPin,
			op.remoteDeviceId,
			this.myDeviceId,
			otherPublicKey,
			keyPair.publicKey,
		);
		const otherDerivedKey = await derive(
			s,
			otherInfo,
			new TextEncoder().encode(finalPin),
		);
		const otherMacCheck = await mac(otherDerivedKey, otherInfo);

		if (!verify(otherMac, otherMacCheck)) {
			throw new SConnectError("PAIRING_FAILED", "Pairing verification failed");
		}

		this.setState("Connected");

		return {
			// todo 用S加密轮换新的对
			myPrivateKey: keyPair.privateKey,
			myPublicKey: keyPair.publicKey,
			remotePublicKey: otherPublicKey,
			createdAt: Date.now(),
			myDeviceId: this.myDeviceId,
			remoteDeviceId: this.remoteId,
		};
	}

	private handlePairRequest(payload: Uint8Array): void {
		if (!this.pairLimiter.canExecute()) {
			// 考虑到id都是临时可变的，无法区分真实设备，所以全部限制
			// todo 中间信息攻击，比如useyourpin dos，或者其它，需要状态机限制顺序和个数
			// todo 提示被频繁占用
			// todo 其他可能的配对方式
			this.signalAdapter
				.send(new Uint8Array([MSG_PAIR_REJECT]))
				.catch(() => {}); // todo 区分拒绝原因
			return;
		}

		const senderId = new TextDecoder().decode(payload);

		const otherPin = Promise.withResolvers<string>();

		const request: PairRequest = {
			remoteDeviceId: senderId,
			inputOtherPin: (pin: string): void => {
				if (!this.validatePin(pin)) {
					otherPin.reject();
					throw new SConnectError("PIN_INVALID", "PIN must be 6 digits");
				}

				otherPin.resolve(pin);
			},
			waitForPairing: () => {
				return this.genWaitForPairing({
					remoteDeviceId: senderId,
					otherPin: otherPin.promise,
					PIN: this.PIN,
				});
			},
			reject: () => {
				// 通知对方配对被拒绝
				this.signalAdapter
					.send(new Uint8Array([MSG_PAIR_REJECT]))
					.catch(() => {});
			},
		};

		this.emit("pairRequest", request);
	}

	// ================= 断开 =================

	disconnect(): void {
		if (this.state === "Idle") return;

		this.sendCipher = null;
		this.receiveCipher = null;

		// 清理回调
		this.onPairReject = null;

		if (this.noise) {
			destroyNoise(this.noise);
			this.noise = null;
		}

		this.signalAdapter.close();
		this.setState("Ready");
		this.emit("disconnect");
	}

	destroy(): void {
		this.sendCipher = null;
		this.receiveCipher = null;

		if (this.noise) {
			destroyNoise(this.noise);
			this.noise = null;
		}

		this.signalAdapter.close();
		this.myDeviceId = "";
		this.myKeyPair = null;
		this.setState("Idle");
	}

	// ================= 数据发送 =================

	async send(payload: string): Promise<void> {
		if (this.state !== "Connected") {
			throw new SConnectError(
				"CHANNEL_NOT_READY",
				`Cannot send in ${this.state} state`,
			);
		}

		const data = new TextEncoder().encode(payload);
		await this.sendData(data);
	}

	async sendBinary(data: ArrayBuffer | Uint8Array): Promise<void> {
		if (this.state !== "Connected") {
			throw new SConnectError(
				"CHANNEL_NOT_READY",
				`Cannot send in ${this.state} state`,
			);
		}

		const buffer = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
		await this.sendData(buffer);
	}

	private async sendData(data: Uint8Array): Promise<void> {
		// 添加应用数据类型字节
		const message = new Uint8Array(1 + data.length);
		message[0] = MSG_APP_DATA;
		message.set(data, 1);

		if (this.sendCipher) {
			const encrypted = this.sendCipher.encrypt(message);
			await this.signalAdapter.send(encrypted);
		} else {
			await this.signalAdapter.send(message);
		}
	}

	// ================= 事件 =================

	on<K extends keyof SecureChannelEvents>(
		event: K,
		callback: SecureChannelEvents[K],
	): void {
		if (!this.eventHandlers.has(event)) {
			this.eventHandlers.set(event, new Set());
		}
		const handlers = this.eventHandlers.get(event);
		if (handlers) {
			handlers.add(callback as (...args: unknown[]) => void);
		}
	}

	off(event: string, callback: (...args: unknown[]) => void): void {
		const handlers = this.eventHandlers.get(event);
		if (handlers) {
			handlers.delete(callback);
		}
	}

	async rotateCredential(): Promise<void> {
		if (this.state !== "Connected") {
			throw new SConnectError(
				"CHANNEL_NOT_READY",
				`Cannot rotate in ${this.state} state`,
			);
		}
		// TODO: implement credential rotation
	}

	// ================= 状态机 =================

	private setState(
		newState: ChannelState,
		handshakeType?: HandshakeType,
	): void {
		const oldState = this.state;
		this.state = newState;
		this.handshakeType =
			handshakeType ?? (newState === "Handshaking" ? this.handshakeType : null);

		// 状态改变时清理所有计时器
		if (oldState !== newState) {
			this.clearAllTimers();
		}
	}

	// ================= 计时器管理 =================

	private createTimer(
		callback: () => void,
		ms: number,
	): ReturnType<typeof setTimeout> {
		const timer = setTimeout(() => {
			this.activeTimers.delete(timer);
			callback();
		}, ms);
		this.activeTimers.add(timer);
		return timer;
	}

	private clearAllTimers(): void {
		for (const timer of this.activeTimers) {
			clearTimeout(timer);
		}
		this.activeTimers.clear();
	}

	// ================= 消息处理 =================

	private handleRawMessage(data: Uint8Array): void {
		const type = data[0];

		// 错误消息任何状态都处理
		if (type === MSG_ERROR) {
			this.handleErrorFromPeer(data.subarray(1));
			return;
		}

		if (this.state !== "Connected") {
			const handlers = this.typeMessageResolvers.get(type);
			if (handlers) {
				handlers.resolve(data.subarray(1));
			} else {
				this.typeMessageQueue.push({ type, payload: data.subarray(1) });
			}
		}

		switch (this.state) {
			case "Idle":
				return;

			case "Ready":
				if (type < 0x20) {
					this.handleProtocolMessage(data);
				} else {
					this.sendErrorToPeer("NOT_CONNECTED", "Peer is not connected");
				}
				return;

			case "Handshaking":
				if (this.isHandshakeMessage(type)) {
					this.handleHandshakeMessage(data);
				} else {
					this.sendErrorToPeer(
						"UNEXPECTED_MESSAGE",
						"Peer is in handshake state",
					);
				}
				return;

			case "Connected":
				// 只拒绝新的配对/连接请求
				if (type === MSG_PAIR_REQUEST) {
					this.sendErrorToPeer(
						"ALREADY_CONNECTED",
						"Peer is already connected",
					);
				} else if (type === MSG_CONNECT_REQUEST) {
					this.sendErrorToPeer(
						"ALREADY_CONNECTED",
						"Peer is already connected",
					);
				} else {
					// 其他都作为应用数据处理（包括协议消息）
					this.handleAppData(data);
				}
				return;
		}
	}

	private isHandshakeMessage(type: number): boolean {
		switch (this.handshakeType) {
			case "pake":
				return (
					type === MSG_APP_DATA ||
					type === MSG_PAIR_REJECT ||
					type === MSG_USE_YOUR_PIN ||
					type === MSG_SPAKE_DATA
				);
			case "ik":
				return type === MSG_NOISE_DATA || type === MSG_APP_DATA;
			case "connect-request":
				return type === MSG_CONNECT_ACCEPT || type === MSG_CONNECT_REJECT;
			case "connect-response":
				return type === MSG_NOISE_DATA || type === MSG_APP_DATA;
			default:
				return false;
		}
	}

	private handleHandshakeMessage(data: Uint8Array): void {
		const type = data[0];
		const payload = data.subarray(1);

		// 处理配对拒绝消息
		if (type === MSG_PAIR_REJECT) {
			this.handlePairReject();
			return;
		}

		// 其他握手消息由各握手方法的消息处理器处理
		if (this.handshakeMessageHandler) {
			this.handshakeMessageHandler(type, payload);
		} else {
			// 如果还未注册处理器（例如正在进行耗时的异步密钥计算），先缓冲消息
			this.handshakeMessageQueue.push({ type, payload });
		}
	}

	private handleProtocolMessage(data: Uint8Array): void {
		const type = data[0];
		const payload = data.subarray(1);

		switch (type) {
			case MSG_PAIR_REQUEST:
				this.handlePairRequest(payload);
				break;
			case MSG_CONNECT_REQUEST:
				this.handleConnectRequest(payload);
				break;
		}
	}

	private handlePairReject(): void {
		if (this.onPairReject) {
			this.onPairReject();
			this.onPairReject = null;
		}
	}

	private handleAppData(data: Uint8Array): void {
		// 移除类型字节
		let payload = new Uint8Array(data.subarray(1));

		if (this.receiveCipher) {
			try {
				payload = new Uint8Array(this.receiveCipher.decrypt(payload));
			} catch {
				this.emit("data", new Uint8Array(payload).buffer as ArrayBuffer, () =>
					this.textDecoder.decode(payload),
				);
				return;
			}
		}

		const text = this.textDecoder.decode(payload);
		try {
			const parsed = JSON.parse(text);
			if (parsed.type === "credential_rotation") {
				this.emit("credentialRotated", {
					remotePublicKey: new Uint8Array(parsed.publicKey),
				} as Credential);
				return;
			}
		} catch {
			// Not JSON
		}

		this.emit("data", payload.buffer, () => this.textDecoder.decode(payload));
	}

	// ================= 错误消息 =================

	private sendErrorToPeer(code: string, message: string): void {
		const errorMsg = JSON.stringify({ code, message });
		const payload = new TextEncoder().encode(errorMsg);
		const msg = new Uint8Array(1 + payload.length);
		msg[0] = MSG_ERROR;
		msg.set(payload, 1);
		this.signalAdapter.send(msg).catch(() => {});
	}

	private handleErrorFromPeer(payload: Uint8Array): void {
		const text = new TextDecoder().decode(payload);
		try {
			const error = JSON.parse(text);
			this.emit("error", new SConnectError(error.code, error.message));
		} catch {
			// ignore
		}
	}

	// ================= 配对请求 =================

	// 当前配对请求的回调函数，用于处理 MSG_PAIR_REJECT 消息
	private onPairReject: (() => void) | null = null;

	// ================= 连接请求 =================

	private async sendConnectRequest(
		credential: CredentialPrivateInfo,
	): Promise<ConnectResult> {
		return new Promise((resolve, reject) => {
			const timeout = this.createTimer(() => {
				this.restoreMessageHandler();
				this.setState("Ready");
				this.sendErrorToPeer("TIMEOUT", "Connect request timeout");
				reject(new SConnectError("TIMEOUT", "Connect request timeout"));
			}, this.options.connectTimeout);

			const messageHandler = (type: number, _payload: Uint8Array) => {
				if (type === MSG_CONNECT_ACCEPT) {
					clearTimeout(timeout);
					this.activeTimers.delete(timeout);
					this.restoreMessageHandler();
					this.setState("Handshaking", "ik");
					this.performIKInitiator(credential).then(resolve).catch(reject);
				} else if (type === MSG_CONNECT_REJECT) {
					clearTimeout(timeout);
					this.activeTimers.delete(timeout);
					this.restoreMessageHandler();
					this.setState("Ready");
					resolve({ success: false });
				}
			};

			this.setHandshakeMessageHandler(messageHandler);

			const myIdBytes = new TextEncoder().encode(this.myDeviceId);
			const message = new Uint8Array(1 + 2 + myIdBytes.length);
			message[0] = MSG_CONNECT_REQUEST;
			new DataView(message.buffer).setUint16(1, myIdBytes.length);
			message.set(myIdBytes, 3);

			this.signalAdapter.send(message).catch((err) => {
				clearTimeout(timeout);
				this.activeTimers.delete(timeout);
				this.restoreMessageHandler();
				this.setState("Ready");
				reject(err);
			});
		});
	}

	// ================= Noise IK =================

	private async performIKInitiator(
		credential: CredentialPrivateInfo,
	): Promise<ConnectResult> {
		try {
			this.noise = createNoise("IK", true, {
				privateKey: credential.myPrivateKey,
				publicKey: credential.myPublicKey,
			});
			initialiseNoise(
				this.noise,
				new Uint8Array(0),
				credential.remotePublicKey,
			);

			const handshakeMessage = sendNoise(this.noise);

			const responsePromise = this.waitForNoiseResponse();

			this.sendHandshakeMessage(MSG_NOISE_DATA, handshakeMessage).catch(
				() => {},
			);

			const response = await responsePromise;
			recvNoise(this.noise, response);

			if (this.noise.complete) {
				if (!this.signalAdapter.supportNativeEncryption) {
					this.sendCipher = createCipher(this.noise.tx);
					this.receiveCipher = createCipher(this.noise.rx);
				}

				this.setState("Connected");
				this.emit("ready");
				return {
					success: true,
					credential: this.buildCredential(credential),
				};
			}

			this.setState("Ready");
			return { success: false };
		} catch {
			this.setState("Ready");
			this.emit(
				"error",
				new SConnectError("IK_HANDSHAKE_FAILED", "Noise IK handshake failed"),
			);
			return { success: false };
		}
	}

	private async performIKResponder(
		credential: CredentialPrivateInfo,
	): Promise<ConnectResult> {
		return new Promise((resolve, reject) => {
			const timeout = this.createTimer(() => {
				this.restoreMessageHandler();
				this.setState("Ready");
				this.sendErrorToPeer("TIMEOUT", "IK handshake timeout");
				reject(new SConnectError("TIMEOUT", "IK handshake timeout"));
			}, this.options.handshakeTimeout);

			const messageHandler = (type: number, payload: Uint8Array) => {
				if (type !== MSG_NOISE_DATA) return;
				try {
					this.noise = createNoise("IK", false, {
						privateKey: credential.myPrivateKey,
						publicKey: credential.myPublicKey,
					});
					initialiseNoise(this.noise, new Uint8Array(0));
					recvNoise(this.noise, payload);

					const responseMsg = sendNoise(this.noise);
					this.sendHandshakeMessage(MSG_NOISE_DATA, responseMsg).catch(
						() => {},
					);

					if (this.noise.complete) {
						if (!this.signalAdapter.supportNativeEncryption) {
							this.sendCipher = createCipher(this.noise.tx);
							this.receiveCipher = createCipher(this.noise.rx);
						}

						this.setState("Connected");
						this.activeTimers.delete(timeout);
						clearTimeout(timeout);
						this.restoreMessageHandler();
						this.emit("ready");
						resolve({
							success: true,
							credential: this.buildCredential(credential),
						});
					} else {
						this.activeTimers.delete(timeout);
						clearTimeout(timeout);
						this.setState("Ready");
						resolve({ success: false });
					}
				} catch {
					this.activeTimers.delete(timeout);
					clearTimeout(timeout);
					this.restoreMessageHandler();
					this.setState("Ready");
					reject(
						new SConnectError(
							"IK_HANDSHAKE_FAILED",
							"Noise IK handshake failed",
						),
					);
				}
			};

			this.setHandshakeMessageHandler(messageHandler);
		});
	}

	private waitForNoiseResponse(): Promise<Uint8Array> {
		return new Promise((resolve, reject) => {
			const timeout = this.createTimer(() => {
				this.restoreMessageHandler();
				this.setState("Ready");
				this.sendErrorToPeer("TIMEOUT", "Noise handshake timeout");
				reject(new SConnectError("TIMEOUT", "Noise handshake timeout"));
			}, this.options.handshakeTimeout);

			const handler = (type: number, payload: Uint8Array) => {
				if (type !== MSG_NOISE_DATA) return;
				this.activeTimers.delete(timeout);
				clearTimeout(timeout);
				this.restoreMessageHandler();
				resolve(payload);
			};

			this.setHandshakeMessageHandler(handler);
		});
	}

	// ================= 工具方法 =================

	private async sendHandshakeMessage(
		type: number,
		payload: Uint8Array,
	): Promise<void> {
		const message = new Uint8Array(1 + payload.length);
		message[0] = type;
		message.set(payload, 1);
		await this.signalAdapter.send(message);
	}

	private async sendTypeMessage(
		type: number,
		payload?: Uint8Array,
	): Promise<void> {
		const message = new Uint8Array(1 + (payload ? payload.length : 0));
		message[0] = type;
		if (payload) {
			message.set(payload, 1);
		}
		await this.signalAdapter.send(message);
	}

	private getTypeMessage(type: number) {
		const p = Promise.withResolvers<Uint8Array>();
		const recived = this.typeMessageQueue.findIndex((msg) => msg.type === type);
		if (recived !== -1) {
			const msg = this.typeMessageQueue.splice(recived, 1)[0];
			p.resolve(msg.payload);
			return p.promise;
		}
		this.typeMessageResolvers.set(type, {
			resolve: (data: Uint8Array) => {
				this.typeMessageResolvers.delete(type);
				p.resolve(data);
			},
			reject: (err: Error) => {
				this.typeMessageResolvers.delete(type);
				p.reject(err);
			},
		});
		return p.promise;
	}

	private setHandshakeMessageHandler(
		handler: (type: number, payload: Uint8Array) => void,
	): void {
		this.handshakeMessageHandler = handler;
		// 处理已经排队的消息
		while (this.handshakeMessageQueue.length > 0) {
			const msg = this.handshakeMessageQueue.shift();
			if (msg) {
				handler(msg.type, msg.payload);
			}
		}
	}

	private restoreMessageHandler(): void {
		this.handshakeMessageHandler = null;
		this.handshakeMessageQueue = [];
	}

	private buildCredential(
		credential: CredentialPrivateInfo | undefined,
	): Credential {
		return {
			myDeviceId: this.myDeviceId,
			remoteDeviceId: this.remoteId,
			myPrivateKey: new Uint8Array(),
			myPublicKey: this.myKeyPair?.publicKey ?? new Uint8Array(),
			remotePublicKey: new Uint8Array(),
			createdAt: Date.now(),
			lastConnected: Date.now(),
			...credential,
		};
	}

	private handleDisconnect(): void {
		if (this.state === "Idle") return;
		this.sendCipher = null;
		this.receiveCipher = null;
		this.setState("Ready");
		this.emit("disconnect");
	}

	private emit<K extends keyof SecureChannelEvents>(
		event: K,
		...args: Parameters<SecureChannelEvents[K]>
	): void {
		const handlers = this.eventHandlers.get(event);
		if (handlers) {
			for (const handler of handlers) {
				try {
					handler(...args);
				} catch (err) {
					console.error(`Error in event handler for ${event}:`, err);
				}
			}
		}
	}

	private generatePin(): string {
		return Math.floor(100000 + Math.random() * 900000).toString();
	}

	private validatePin(pin: string): boolean {
		return /^\d{6}$/.test(pin);
	}

	private wrapError(error: unknown): SConnectError {
		if (error instanceof SConnectError) return error;
		return new SConnectError(
			"ADAPTER_ERROR",
			error instanceof Error ? error.message : String(error),
		);
	}

	private async generateKeyPair(): Promise<KeyPair> {
		const keyPair = await crypto.subtle.generateKey(
			{ name: "X25519" } as AlgorithmIdentifier,
			true,
			["deriveBits"],
		);

		const publicKeyBuffer = await crypto.subtle.exportKey(
			"raw",
			(keyPair as CryptoKeyPair).publicKey,
		);
		const privateKeyBuffer = await crypto.subtle.exportKey(
			"pkcs8",
			(keyPair as CryptoKeyPair).privateKey,
		);

		return {
			publicKey: new Uint8Array(publicKeyBuffer),
			privateKey: new Uint8Array(privateKeyBuffer).subarray(16),
		};
	}
}

export async function generateKeyPair(): Promise<KeyPair> {
	const keyPair = await crypto.subtle.generateKey(
		{ name: "X25519" } as AlgorithmIdentifier,
		true,
		["deriveBits"],
	);

	const publicKeyBuffer = await crypto.subtle.exportKey(
		"raw",
		(keyPair as CryptoKeyPair).publicKey,
	);
	const privateKeyBuffer = await crypto.subtle.exportKey(
		"pkcs8",
		(keyPair as CryptoKeyPair).privateKey,
	);

	return {
		publicKey: new Uint8Array(publicKeyBuffer),
		privateKey: new Uint8Array(privateKeyBuffer).subarray(16),
	};
}

// todo 更安全做法
export function blind(pin: string, publicKey: Uint8Array): Uint8Array {
	// 将 PIN 转换为 Uint8Array
	const pinBytes = new TextEncoder().encode(pin);

	// 创建一个新的 Uint8Array 来存储盲化后的公钥
	const blindedKey = new Uint8Array(publicKey.length);

	// 对每个字节进行盲化处理
	for (let i = 0; i < publicKey.length; i++) {
		blindedKey[i] = publicKey[i] ^ pinBytes[i % pinBytes.length];
	}

	return blindedKey;
}

export function deBlind(blindedKey: Uint8Array, pin: string): Uint8Array {
	// 将 PIN 转换为 Uint8Array
	const pinBytes = new TextEncoder().encode(pin);

	// 创建一个新的 Uint8Array 来存储去盲化后的公钥
	const originalKey = new Uint8Array(blindedKey.length);

	// 对每个字节进行去盲化处理
	for (let i = 0; i < blindedKey.length; i++) {
		originalKey[i] = blindedKey[i] ^ pinBytes[i % pinBytes.length];
	}

	return originalKey;
}

export async function dh(
	privateKey: Uint8Array,
	publicKey: Uint8Array,
): Promise<Uint8Array> {
	const privKey = await crypto.subtle.importKey(
		"pkcs8",
		buildPkcs8(privateKey),
		"X25519",
		false,
		["deriveBits"],
	);
	const pubKey = await crypto.subtle.importKey(
		"raw",
		publicKey as unknown as BufferSource,
		"X25519",
		false,
		[],
	);
	const bits = await crypto.subtle.deriveBits(
		{ name: "X25519", public: pubKey },
		privKey,
		256,
	);
	return new Uint8Array(bits);
}

function buildPkcs8(rawPrivKey: Uint8Array): ArrayBuffer {
	const header = new Uint8Array([
		0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
		0x04, 0x22, 0x04, 0x20,
	]);
	const buf = new Uint8Array(header.length + rawPrivKey.length);
	buf.set(header, 0);
	buf.set(rawPrivKey, header.length);
	return buf.buffer;
}

function buildPairingInfo(
	pin: string,
	localId: string,
	remoteId: string,
	localEphemeralPk: Uint8Array,
	remoteEphemeralPk: Uint8Array,
): ArrayBuffer {
	const enc = new TextEncoder();
	const pinBytes = enc.encode(pin);
	const localIdBytes = enc.encode(localId);
	const remoteIdBytes = enc.encode(remoteId);

	const buf = new Uint8Array(
		[
			pinBytes,
			localIdBytes,
			remoteIdBytes,
			localEphemeralPk,
			remoteEphemeralPk,
		].flatMap((arr) => [...arr]),
	);

	return buf.buffer;
}

async function derive(
	ikm: Uint8Array,
	info: ArrayBuffer,
	salt: Uint8Array,
): Promise<Uint8Array> {
	const key = await crypto.subtle.importKey(
		"raw",
		ikm as unknown as BufferSource,
		"HKDF",
		false,
		["deriveBits"],
	);
	const bits = await crypto.subtle.deriveBits(
		{
			name: "HKDF",
			hash: "SHA-256",
			salt: salt as unknown as BufferSource,
			info,
		},
		key,
		256,
	);
	return new Uint8Array(bits);
}

async function mac(key: Uint8Array, data: ArrayBuffer): Promise<Uint8Array> {
	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		key as unknown as BufferSource,
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const sig = await crypto.subtle.sign("HMAC", cryptoKey, data);
	return new Uint8Array(sig);
}

function verify(key: Uint8Array, key2: Uint8Array) {
	if (key.byteLength !== key2.byteLength) return false;
	const a = key;
	const b = key2;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
	return diff === 0;
}
