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

interface KeyPair {
	publicKey: Uint8Array;
	privateKey: Uint8Array;
}

// 协议消息类型
const MSG_PAIR_REQUEST = 1;
const MSG_USE_YOUR_PIN = 2; // 通知对方使用自己的 PIN
const MSG_PAIR_REJECT = 7; // 拒绝配对请求
const MSG_CONNECT_REQUEST = 3;
const MSG_CONNECT_ACCEPT = 4;
const MSG_ERROR = 6;
const MSG_SPAKE_DATA = 11;
const MSG_BLIND_PUBLIC_KEY = 12;
const MSG_CONNECT_PUBLIC_KEY = 13;
const MSG_CONNECT_MAC_VER = 14;
const MSG_SIGNING_PUBLIC_KEY = 15;

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
	private cipher: cipher | null = null;
	private PIN = "";
	private eventHandlers: Map<string, Set<(...args: unknown[]) => void>> =
		new Map();

	// 状态机
	private state: ChannelState = "Idle";
	private handshakeType: HandshakeType = null;
	private typeMessageQueue: { type: number; payload: Uint8Array }[] = [];
	private typeMessageResolvers: Map<
		number,
		{ resolve: (data: Uint8Array) => void; reject: (err: Error) => void }
	> = new Map();

	// 设备身份
	private myDeviceId = "";

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

		this.setState("Ready");
	}

	// ================= 连接 =================

	async tryConnect(credential?: CredentialPrivateInfo): Promise<ConnectResult> {
		if (this.state !== "Ready") {
			return { success: false };
		}

		if (!this.remoteId) {
			return { success: false, reason: "NEEDS_PAIRING" };
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
				await this.sendTypeMessage(
					MSG_CONNECT_REQUEST,
					new TextEncoder().encode(this.myDeviceId),
				);
				const r = (await this.getTypeMessage(MSG_CONNECT_ACCEPT))[0];
				if (r === 1) return this.connectWithCredential(credential);
			}

			return { success: false, reason: "NEEDS_PAIRING" };
		} catch (error) {
			this.setState("Ready");
			this.emit("error", this.wrapError(error));
			return { success: false };
		}
	}

	private async connectWithCredential(
		credential: CredentialPrivateInfo,
	): Promise<ConnectResult> {
		const eph = await generateKeyPair();
		const ephSig = await sigh(credential.myPrivateKey, eph.publicKey);
		const m = concatUint8Arrays([eph.publicKey, ephSig]);
		await this.sendTypeMessage(MSG_CONNECT_PUBLIC_KEY, m);
		const otherM = await this.getTypeMessage(MSG_CONNECT_PUBLIC_KEY);
		const otherPubKey = otherM.subarray(0, eph.publicKey.length);
		const otherSig = otherM.subarray(eph.publicKey.length);
		const sigValid = await verifySignature(
			credential.remotePublicKey,
			otherPubKey,
			otherSig,
		);
		if (!sigValid) {
			this.setState("Ready");
			return { success: false, reason: "NEEDS_PAIRING" };
		}

		const dhSecret = await dh(eph.privateKey, otherPubKey);

		const info = buildConnectionInfo(
			this.myDeviceId,
			this.remoteId,
			eph.publicKey,
			otherPubKey,
		);
		const derivedKey = await derive(dhSecret, info, new Uint8Array(0));
		const myMac = await mac(derivedKey, info);
		await this.sendTypeMessage(MSG_CONNECT_MAC_VER, myMac);
		const otherMac = await this.getTypeMessage(MSG_CONNECT_MAC_VER);

		const otherInfo = buildConnectionInfo(
			this.remoteId,
			this.myDeviceId,
			otherPubKey,
			eph.publicKey,
		);
		const otherDerivedKey = await derive(
			dhSecret,
			otherInfo,
			new Uint8Array(0),
		);
		const otherMacCheck = await mac(otherDerivedKey, otherInfo);

		const macValid = verify(otherMac, otherMacCheck);
		if (!macValid) {
			this.setState("Ready");
			return { success: false, reason: "NEEDS_PAIRING" };
		}

		if (!this.signalAdapter.supportNativeEncryption) {
			this.cipher = new cipher(derivedKey, derivedKey);
		}
		this.setState("Connected");
		this.emit("ready");
		return { success: true, credential: this.buildCredential(credential) };
	}

	private handleConnectRequest(payload: Uint8Array): void {
		const senderId = new TextDecoder().decode(payload);

		if (senderId !== this.remoteId) {
			this.sendTypeMessage(MSG_CONNECT_ACCEPT, new Uint8Array([0])).catch(
				() => {},
			);
			return;
		}

		if (!this.connectLimiter.canExecute()) {
			// todo 提示被频繁占用
			this.sendTypeMessage(MSG_CONNECT_ACCEPT, new Uint8Array([0])).catch(
				() => {},
			);
			return;
		}

		const request: ConnectRequest = {
			remoteDeviceId: senderId,
			accept: (credential: Credential): Promise<ConnectResult> => {
				this.setState("Handshaking", "connect-response");
				this.sendTypeMessage(MSG_CONNECT_ACCEPT, new Uint8Array([1])).catch(
					() => {},
				);
				return this.connectWithCredential(credential);
			},
			reject: () => {
				this.sendTypeMessage(MSG_CONNECT_ACCEPT, new Uint8Array([0])).catch(
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

		// todo 派生
		const signingKeyPair = await generateSigningKeyPair();
		await this.sendTypeMessage(
			MSG_SIGNING_PUBLIC_KEY,
			signingKeyPair.publicKey,
		);
		const remoteSigningPublicKey = await this.getTypeMessage(
			MSG_SIGNING_PUBLIC_KEY,
		);

		if (!remoteSigningPublicKey) {
			throw new SConnectError(
				"PAIRING_FAILED",
				"Failed to receive signing public key",
			);
		}

		if (!this.signalAdapter.supportNativeEncryption) {
			// todo 派生
			this.cipher = new cipher(
				await dh(keyPair.privateKey, otherPublicKey),
				await dh(keyPair.privateKey, otherPublicKey),
			);
		}

		this.setState("Connected");

		return {
			myPrivateKey: signingKeyPair.privateKey,
			myPublicKey: signingKeyPair.publicKey,
			remotePublicKey: remoteSigningPublicKey,
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
			this.sendTypeMessage(MSG_PAIR_REJECT).catch(() => {}); // todo 区分拒绝原因
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
				this.sendTypeMessage(MSG_PAIR_REJECT).catch(() => {});
			},
		};

		this.emit("pairRequest", request);
	}

	// ================= 断开 =================

	disconnect(): void {
		if (this.state === "Idle") return;

		this.cipher = null;

		this.signalAdapter.close();
		this.setState("Ready");
		this.emit("disconnect");
	}

	destroy(): void {
		this.cipher = null;

		this.signalAdapter.close();
		this.myDeviceId = "";
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
		if (this.cipher) {
			const encrypted = await this.cipher.encrypt(data);
			await this.signalAdapter.send(encrypted);
		} else {
			await this.signalAdapter.send(data);
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

	private clearAllTimers(): void {
		for (const timer of this.activeTimers) {
			clearTimeout(timer);
		}
		this.activeTimers.clear();
	}

	// ================= 消息处理 =================

	private handleRawMessage(data: Uint8Array): void {
		if (this.state === "Connected") {
			this.handleAppData(data).catch(() => {});
		} else {
			const type = data[0];
			const payload = data.subarray(1);

			// 错误消息任何状态都处理
			if (type === MSG_ERROR) {
				this.handleErrorFromPeer(payload);
				return;
			}

			const handlers = this.typeMessageResolvers.get(type);
			if (handlers) {
				handlers.resolve(payload);
			} else {
				this.typeMessageQueue.push({ type, payload });
			}

			switch (this.state) {
				case "Idle":
					return;

				case "Ready":
					switch (type) {
						case MSG_PAIR_REQUEST:
							this.handlePairRequest(payload);
							break;
						case MSG_CONNECT_REQUEST:
							this.handleConnectRequest(payload);
							break;
					}
					return;
			}
		}
	}

	private async handleAppData(data: Uint8Array): Promise<void> {
		let payload = data;

		if (this.cipher) {
			try {
				payload = new Uint8Array(await this.cipher.decrypt(payload));
			} catch {
				this.emit("data", new Uint8Array(payload).buffer as ArrayBuffer, () =>
					this.textDecoder.decode(payload),
				);
				return;
			}
		}

		this.emit("data", payload.buffer as ArrayBuffer, () =>
			this.textDecoder.decode(payload),
		);
	}

	// ================= 错误消息 =================

	private handleErrorFromPeer(payload: Uint8Array): void {
		const text = new TextDecoder().decode(payload);
		try {
			const error = JSON.parse(text);
			this.emit("error", new SConnectError(error.code, error.message));
		} catch {
			// ignore
		}
	}

	// ================= 工具方法 =================

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
				clearTimeout(timer);
				p.resolve(data);
			},
			reject: (err: Error) => {
				this.typeMessageResolvers.delete(type);
				clearTimeout(timer);
				p.reject(err);
			},
		});
		const timer = setTimeout(() => {
			this.typeMessageResolvers.delete(type);
			p.reject(new SConnectError("TIMEOUT", `Timeout waiting for message type ${type}`));
		}, this.options.handshakeTimeout);
		this.activeTimers.add(timer);
		return p.promise;
	}

	private buildCredential(
		credential: CredentialPrivateInfo | undefined,
	): Credential {
		return {
			myDeviceId: this.myDeviceId,
			remoteDeviceId: this.remoteId,
			myPrivateKey: new Uint8Array(),
			myPublicKey:  new Uint8Array(),
			remotePublicKey: new Uint8Array(),
			createdAt: Date.now(),
			lastConnected: Date.now(),
			...credential,
		};
	}

	private handleDisconnect(): void {
		if (this.state === "Idle") return;
		this.cipher = null;
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

export async function generateSigningKeyPair(): Promise<KeyPair> {
	const keyPair = await crypto.subtle.generateKey("Ed25519", true, [
		"sign",
		"verify",
	]);
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

export class cipher {
	private sendCryptoKey: CryptoKey | null = null;
	private receiveCryptoKey: CryptoKey | null = null;

	constructor(
		private sendKey: Uint8Array,
		private receiveKey: Uint8Array,
	) {}

	private async getSendKey(): Promise<CryptoKey> {
		if (!this.sendCryptoKey) {
			this.sendCryptoKey = await crypto.subtle.importKey(
				"raw",
				this.sendKey as unknown as BufferSource,
				{ name: "AES-GCM" },
				false,
				["encrypt"],
			);
		}
		return this.sendCryptoKey;
	}

	private async getReceiveKey(): Promise<CryptoKey> {
		if (!this.receiveCryptoKey) {
			this.receiveCryptoKey = await crypto.subtle.importKey(
				"raw",
				this.receiveKey as unknown as BufferSource,
				{ name: "AES-GCM" },
				false,
				["decrypt"],
			);
		}
		return this.receiveCryptoKey;
	}

	async encrypt(data: Uint8Array): Promise<Uint8Array> {
		const key = await this.getSendKey();
		const iv = crypto.getRandomValues(new Uint8Array(12));
		const encrypted = await crypto.subtle.encrypt(
			{ name: "AES-GCM", iv },
			key,
			data as unknown as BufferSource,
		);
		const result = new Uint8Array(iv.length + encrypted.byteLength);
		result.set(iv);
		result.set(new Uint8Array(encrypted), iv.length);
		return result;
	}

	async decrypt(data: Uint8Array): Promise<Uint8Array> {
		const key = await this.getReceiveKey();
		const iv = new Uint8Array(data.buffer, data.byteOffset, 12);
		const ciphertext = new Uint8Array(data.buffer, data.byteOffset + 12);
		const decrypted = await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: iv as unknown as BufferSource },
			key,
			ciphertext as unknown as BufferSource,
		);
		return new Uint8Array(decrypted);
	}
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
		buildX25519Pkcs8(privateKey),
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

function buildX25519Pkcs8(rawPrivKey: Uint8Array): ArrayBuffer {
	const header = new Uint8Array([
		0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
		0x04, 0x22, 0x04, 0x20,
	]);
	const buf = new Uint8Array(header.length + rawPrivKey.length);
	buf.set(header, 0);
	buf.set(rawPrivKey, header.length);
	return buf.buffer;
}

function buildEd25519Pkcs8(rawPrivKey: Uint8Array): ArrayBuffer {
	const header = new Uint8Array([
		0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
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

function concatUint8Arrays(arrays: Uint8Array[]): Uint8Array {
	const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
	const result = new Uint8Array(totalLength);
	let offset = 0;
	for (const arr of arrays) {
		result.set(arr, offset);
		offset += arr.length;
	}
	return result;
}

export async function sigh(
	privateKey: Uint8Array,
	data: Uint8Array,
): Promise<Uint8Array> {
	const key = await crypto.subtle.importKey(
		"pkcs8",
		buildEd25519Pkcs8(privateKey),
		"Ed25519",
		false,
		["sign"],
	);
	const sig = await crypto.subtle.sign(
		"Ed25519",
		key,
		data as unknown as BufferSource,
	);
	return new Uint8Array(sig);
}

export async function verifySignature(
	publicKey: Uint8Array,
	data: Uint8Array,
	signature: Uint8Array,
): Promise<boolean> {
	const key = await crypto.subtle.importKey(
		"raw",
		publicKey as unknown as BufferSource,
		"Ed25519",
		false,
		["verify"],
	);
	return crypto.subtle.verify(
		"Ed25519",
		key,
		signature as unknown as BufferSource,
		data as unknown as BufferSource,
	);
}

function buildConnectionInfo(
	localId: string,
	remoteId: string,
	localEphemeralPk: Uint8Array,
	remoteEphemeralPk: Uint8Array,
): ArrayBuffer {
	const enc = new TextEncoder();
	const localIdBytes = enc.encode(localId);
	const remoteIdBytes = enc.encode(remoteId);
	return concatUint8Arrays([
		localIdBytes,
		remoteIdBytes,
		localEphemeralPk,
		remoteEphemeralPk,
	]).buffer as ArrayBuffer;
}
