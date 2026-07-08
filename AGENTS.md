一个带有身份验证、加密的通信连接库。

下面是核心思想：

- 点对点，多连接需要自己处理
- 连接层可以替换，如webrtc，或者其它有线无线通信
- 先通过id连接，各自显示PIN，一方输入对方的即可
- 身份验证后可以外部应用层记忆，下次传入后可以自动连接

API设计

```js
const channelA = new SConnect(adapterA);
// id自己生成。id对应的不是设备id，而是连接的端点id
// 也就是，如果一个设备创建了n个SConnect，那就有n个id
await channelA.init("device-a", "device-b");
// 在受信通道不用验证身份
const result = await channelA.tryConnect();
// 或者已经验证过身份，用外部记忆的credential
const result = await channelA.tryConnect(credentialOfB);

if (result.success) {
    console.log("连接成功");
} else {
    if (result.reason === "NEEDS_PAIRING") {
        // 应用层根据此进行配对流程
    }
}

channelA.on("connectRequest", async (request) => {
    // 从本地存储加载对方的 Credential
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

// 配对
const pairing = await channelA.pairInit({
    myDeviceId: "device-a",
    remoteDeviceId: "device-b",
});
// 显示 PIN 给用户
console.log("请将此 PIN 告诉对方:", pairing.pin);
// 等待对方输入 PIN 完成配对
const credentialA = await pairing.waitForPairing();
console.log("A 配对成功", credentialA);

// 也接收来自对方的配对
channelA.on("pairRequest", async (request) => {
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
```

## 要求

使用 Web Crypto API 的 SubtleCrypto 接口

web、nodejs兼容
