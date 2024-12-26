export = Strategy;
declare function Strategy(options: any, verify: any): void;
declare class Strategy {
    constructor(options: any, verify: any);
    name: string;
    _verify: any;
    _opts: any;
    clockOffset: any;
    clockMargin: any;
    authUri: any;
    keyId: any;
    key: any;
    /**
     * Authenticate request
     *
     * @param {Object} req
     * @api protected
     */
    authenticate(req: any): any;
    redirectToAuthenticate(req: any, res: any): void;
    processResponse(req: any): any;
}
declare namespace Strategy {
    export { Strategy };
}
