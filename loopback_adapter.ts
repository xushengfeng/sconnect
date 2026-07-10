import type {
	TrustedSignalingAdapter,
	UntrustedSignalingAdapter,
} from "./sconnect_type";

type MessageHandler = (data: Uint8Array) => void;
type CloseHandler = () => void;
type ErrorHandler = (err: Error) => void;

export class LoopbackAdapterManager {
	private m = new Map<string, LoopbackAdapter>();
	newAdapter() {
		return new LoopbackAdapter(this);
	}
	setId(id: string, adapter: LoopbackAdapter) {
		this.m.set(id, adapter);
	}
	connect(id1: string, id2: string) {
		const a = this.m.get(id1);
		const b = this.m.get(id2);
		if (!a || !b) {
			throw new Error("Adapter not found");
		}
		a.peer = b;
		b.peer = a;
	}
	static createPair(): [LoopbackAdapter, LoopbackAdapter] {
		const manager = new LoopbackAdapterManager();
		const a = new LoopbackAdapter(manager);
		const b = new LoopbackAdapter(manager);
		return [a, b];
	}
}

export class UntrustedLoopbackAdapterManager {
	private m = new Map<string, UntrustedLoopbackAdapter>();
	newAdapter(supportNativeEncryption = true) {
		return new UntrustedLoopbackAdapter(this, supportNativeEncryption);
	}
	setId(id: string, adapter: UntrustedLoopbackAdapter) {
		this.m.set(id, adapter);
	}
	connect(id1: string, id2: string) {
		const a = this.m.get(id1);
		const b = this.m.get(id2);
		if (!a || !b) {
			throw new Error("Adapter not found");
		}
		a.peer = b;
		b.peer = a;
	}
	static createPair(
		supportNativeEncryption = true,
	): [UntrustedLoopbackAdapter, UntrustedLoopbackAdapter] {
		const manager = new UntrustedLoopbackAdapterManager();
		const a = new UntrustedLoopbackAdapter(manager, supportNativeEncryption);
		const b = new UntrustedLoopbackAdapter(manager, supportNativeEncryption);
		return [a, b];
	}
}

/**
 * 受信任的本地回环信令适配器，用于测试。
 * 外部已验证身份，不加密。
 */
export class LoopbackAdapter implements TrustedSignalingAdapter {
	trustIdentity = true as const;
	supportNativeEncryption = false as const;

	peer: LoopbackAdapter | null = null;
	private id: string | null = null;
	private messageHandler: MessageHandler | null = null;
	private closeHandler: CloseHandler | null = null;

	constructor(private manager: LoopbackAdapterManager) {}

	async init(_myId: string): Promise<void> {
		this.id = _myId;
		this.manager.setId(_myId, this);
	}

	async connect(_id: string): Promise<void> {
		if (!this.id) {
			throw new Error("Adapter not initialized");
		}
		this.manager.connect(this.id, _id);
	}

	async send(data: Uint8Array): Promise<void> {
		if (!this.peer) {
			throw new Error("No peer connected");
		}
		await new Promise((resolve) => setTimeout(resolve, 0));
		if (this.peer.messageHandler) {
			this.peer.messageHandler(new Uint8Array(data));
		}
	}

	close(): void {
		if (this.peer?.closeHandler) {
			this.peer.closeHandler();
		}
		this.peer = null;
	}

	onMessage(handler: MessageHandler): void {
		this.messageHandler = handler;
	}

	onClose(handler: CloseHandler): void {
		this.closeHandler = handler;
	}

	onError(_handler: ErrorHandler): void {}
}

/**
 * 不受信任的本地回环适配器，用于测试。
 * 需要内部 PAKE 验证，可选加密。
 */
export class UntrustedLoopbackAdapter implements UntrustedSignalingAdapter {
	trustIdentity = false as const;
	supportNativeEncryption: boolean;

	id: string | null = null;
	peer: UntrustedLoopbackAdapter | null = null;
	private messageHandler: MessageHandler | null = null;
	private closeHandler: CloseHandler | null = null;

	constructor(
		private manager: UntrustedLoopbackAdapterManager,
		supportNativeEncryption = true,
	) {
		this.supportNativeEncryption = supportNativeEncryption;
	}

	async init(_myId: string): Promise<void> {
		this.id = _myId;
		this.manager.setId(_myId, this);
	}

	async connect(_id: string): Promise<void> {
		if (!this.id) {
			throw new Error("Adapter not initialized");
		}
		this.manager.connect(this.id, _id);
	}

	async send(data: Uint8Array): Promise<void> {
		if (!this.peer) {
			throw new Error("No peer connected");
		}
		await new Promise((resolve) => setTimeout(resolve, 0));
		if (this.peer.messageHandler) {
			this.peer.messageHandler(new Uint8Array(data));
		}
	}

	close(): void {
		if (this.peer?.closeHandler) {
			this.peer.closeHandler();
		}
		this.peer = null;
	}

	onMessage(handler: MessageHandler): void {
		this.messageHandler = handler;
	}

	onClose(handler: CloseHandler): void {
		this.closeHandler = handler;
	}

	onError(_handler: ErrorHandler): void {}
}
