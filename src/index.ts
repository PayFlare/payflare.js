import axios, { AxiosInstance } from 'axios';
import {timingSafeEqual, createHmac} from 'crypto';

export type createPaymentUserAPI = {
    name: string;
    currency: "USD" | "EUR" | "SAT";
    amount: number;
    description?: string | undefined;
    methods?: ("ONCHAIN" | "LIGHTNING")[] | undefined;
    expires_at?: number | undefined;
    payer_email?: string | undefined;
    redirect_after?: string | undefined;
    message_after?: string | undefined;
}
export type WebhookPaidPayload = {
    id: string,
    amount_invoiced: number,
    amount_paid: number,
    created_at: number,
    invoice_currency: string,
    paid_at: number,
    payment_method: "LIGHTNING" | "ONCHAIN",
    name: string,
    product_id?:string,
    type: "PAYMENT_PAID",
    sats_paid: number,

}

class PaylfareException extends Error {
    code: number;
    type: string;
    data: any;
    
    constructor(message:string, code:number, type:string, data:any) {
        super(message);
        this.code = code;
        this.type = type;
        this.data = data;
    }
  }
class Payments {
    constructor(private client: AxiosInstance) { }
    async create(data: createPaymentUserAPI) {
        const res = await this.client.post("/payments", data)
        if(res.status !== 200) throw new PaylfareException("Error creating payment", res.status, "HTTP", res.data)
        return {checkout: `https://payflare.io/pay/${res.data.id}`,...res.data} as {checkout:string, id: string, ok: boolean }
    }

}
class Webhooks {

    constructor() { }
    private verifySignature(payload: string, signature: string, webhook_secret: string) {
        const reg = /^sig=(?<sig>[0-9a-f]{64}),t=(?<exp>[0-9]{10,14})$/
        const res = reg.exec(signature)
        if(!res) throw new PaylfareException("Invalid signature", 400, "SIGNATURE", {payload, signature})
        const timeNow = Math.floor(Date.now() / 1000)
        const timeData = parseInt(res.groups!.exp!)
        if((timeNow - timeData) > 60 * 3) throw new PaylfareException("Signature expired", 400, "SIGNATURE", {payload, signature})
        const hmac = createHmac("sha256", webhook_secret).update(payload).digest("hex")
        if(!timingSafeEqual(Buffer.from(hmac), Buffer.from(res.groups!.sig!))) throw new PaylfareException("Invalid signature", 400, "SIGNATURE", {payload, signature})
        return true
    }
    constructEvent(payload: string, signature: string, webhook_secret: string) {
        if(this.verifySignature(payload, signature, webhook_secret) !== true) {
            throw new PaylfareException("Invalid signature", 400, "SIGNATURE", {payload, signature})
        }
        const data = JSON.parse(payload)
        if(data.type === "PAYMENT_PAID") return data as WebhookPaidPayload
        throw new PaylfareException("Invalid event type", 400, "EVENT", data)
    }
}
export class Payflare {
    private api: AxiosInstance;
    payments: Payments;
    webhooks: Webhooks
    constructor(api_secet?: string) {
        this.api = axios.create({
            baseURL: 'https://api.payflare.io/',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'api-auth': `Token ${api_secet ?? ""}`
            },
            validateStatus: null
        });
        this.payments = new Payments(this.api);
        this.webhooks = new Webhooks();
    }
    
}
