export type JwtPayload = {
    id: number | string;
    role?: string | null;
    roles: string[];
    email?: string | null;
    fullName?: string | null;
    phone?: string | null;
    [key: string]: unknown;
};
export type PasswordHashAlgorithm = 'scrypt' | 'sha256';
export type PasswordScryptOptions = {
    N: number;
    r: number;
    p: number;
    maxmem: number;
};
export declare const getExpiresAt: (value: string | number | undefined, fallback: number) => Date;
export declare const isExpired: (value: Date | string | null | undefined) => boolean;
export declare const randomToken: (bytes?: number) => string;
export declare const randomCode: (length?: number) => string;
export declare const randomSalt: () => string;
export declare const getPasswordHashAlgorithm: () => PasswordHashAlgorithm;
export declare const getScryptOptions: () => PasswordScryptOptions;
export declare const hashPassword: (password: string, salt: string, algorithm?: PasswordHashAlgorithm) => string;
export declare const verifyPassword: (password: string, salt: string, hash: string, algorithm?: PasswordHashAlgorithm) => boolean;
export declare const normalizeEmail: (value: unknown) => string | null;
export declare const normalizePhone: (value: unknown) => string | null;
export declare const signJwt: (payload: JwtPayload, { secret, expiresIn, }?: {
    secret?: string;
    expiresIn?: string | number;
}) => string;
//# sourceMappingURL=auth.d.ts.map