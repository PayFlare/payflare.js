"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Payflare = void 0;
const axios_1 = __importDefault(require("axios"));
const crypto_1 = require("crypto");
class PaylfareException extends Error {
    constructor(message, code, type, data) {
        super(message);
        this.code = code;
        this.type = type;
        this.data = data;
    }
}
class Payments {
    constructor(client) {
        this.client = client;
    }
    async create(data) {
        const res = await this.client.post("/payments", data);
        if (res.status !== 200)
            throw new PaylfareException("Error creating payment", res.status, "HTTP", res.data);
        return { checkout: `https://payflare.io/pay/${res.data.id}`, ...res.data };
    }
}
class Webhooks {
    constructor() { }
    verifySignature(payload, signature, webhook_secret) {
        const reg = /^sig=(?<sig>[0-9a-f]{64}),t=(?<exp>[0-9]{10,14})$/;
        const res = reg.exec(signature);
        if (!res)
            throw new PaylfareException("Invalid signature", 400, "SIGNATURE", { payload, signature });
        const timeNow = Math.floor(Date.now() / 1000);
        const timeData = parseInt(res.groups.exp);
        if ((timeNow - timeData) > 60 * 3)
            throw new PaylfareException("Signature expired", 400, "SIGNATURE", { payload, signature });
        const hmac = (0, crypto_1.createHmac)("sha256", webhook_secret).update(payload).digest("hex");
        if (!(0, crypto_1.timingSafeEqual)(Buffer.from(hmac), Buffer.from(res.groups.sig)))
            throw new PaylfareException("Invalid signature", 400, "SIGNATURE", { payload, signature });
        return true;
    }
    constructEvent(payload, signature, webhook_secret) {
        if (this.verifySignature(payload, signature, webhook_secret) !== true) {
            throw new PaylfareException("Invalid signature", 400, "SIGNATURE", { payload, signature });
        }
        const data = JSON.parse(payload);
        if (data.type === "PAYMENT_PAID")
            return data;
        throw new PaylfareException("Invalid event type", 400, "EVENT", data);
    }
}
class Payflare {
    constructor(api_secet) {
        this.api = axios_1.default.create({
            baseURL: 'https://api.payflare.io/',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'api-auth': `Token ${api_secet}`
            },
            validateStatus: null
        });
        this.payments = new Payments(this.api);
        this.webhooks = new Webhooks();
    }
}
exports.Payflare = Payflare;
