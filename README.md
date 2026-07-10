# myde-remote-connect

远程连接模块，支持配对和自动连接。

## 功能特性

- 端到端加密
- 通过 PIN 码配对
- 支持凭证保存和重连
- 多种适配器: 支持 PeerJS (WebRTC)、本地回环等
- 纯 ESM 模块（浏览器、nodejs、electron兼容）

## 快速开始

### 不受信任信道（如网络）- PAKE 配对

```typescript
import { SConnect } from "myde-remote-connect/sconnect";
import { UntrustedLoopbackAdapterManager } from "myde-remote-connect/loopback_adapter";

// 创建适配器对
const [adapterA, adapterB] = UntrustedLoopbackAdapterManager.createPair();

// 创建通道实例
const channelA = new SConnect(adapterA, { handshakeTimeout: 10000 });
const channelB = new SConnect(adapterB, { handshakeTimeout: 10000 });

// 初始化，id需要手动创建，建议使用crypto.randomUUID()
await channelA.init("device-a");
await channelB.init("device-b");

// ===== 接收方 B：监听配对请求 =====
channelB.on("pairRequest", async (request) => {
    console.log(`${request.remoteDeviceId} 请求配对`);

    // 用户输入对方显示的 PIN
    const pin = await getUserInput("请输入对方显示的 PIN:");

    // 接受配对
    request.inputOtherPin(pin);
    const credential = await request.waitForPairing();
    console.log("B 配对成功", credential);

    // 或者拒绝配对
    // request.reject();
});

// ===== 发起方 A：发起配对 =====
const pairing = await channelA.pairInit({
    myDeviceId: "device-a",
    remoteDeviceId: "device-b",
});

// 显示 PIN 给用户
console.log("请将此 PIN 告诉对方:", pairing.pin);

// 等待对方输入 PIN 完成配对
const credentialA = await pairing.waitForPairing();
console.log("A 配对成功", credentialA);

// 任何一方都可以输入pin

// 现在可以安全通信
await channelA.send("Secure message");
```

### 使用凭证重连

```typescript
// A 有 B 的 Credential（之前配对获得的）
// 必须提供对方 id，Credential 里有
await channelA.init("device-a", "device-b");
await channelB.init("device-b", "device-a");
// ===== 发起方 A =====
const credentialOfB = loadCredential("device-b");
const result = await channelA.tryConnect(credentialOfB);
if (result.success) {
    console.log("连接成功");
}
// 如果 { success: false, reason: "NEEDS_PAIRING" } ，需要重新执行配对流程

// ===== 接收方 B =====
channelB.on("connectRequest", async (request) => {
    console.log(`${request.remoteDeviceId} 请求连接`);

    // 从本地存储加载 B 保存的关于 A 的 Credential
    const credentialOfA = loadCredential(request.remoteDeviceId);

    if (credentialOfA) {
        // 使用保存的 Credential 接受连接
        const result = await request.accept(credentialOfA);
        console.log("连接成功", result);
    } else {
        // 没有保存的凭证，拒绝
        request.reject();
    }
});
```

## 更多

见[AGENTS.md](AGENTS.md)

## 许可证

AGPL-3.0-only
