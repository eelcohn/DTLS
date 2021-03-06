static DH *get_dh8192(void)
{
    static unsigned char dhp_8192[] = {
        0x8C, 0x3D, 0x17, 0x1A, 0x23, 0x2E, 0x68, 0x3F, 0x8B, 0xC2,
        0xFB, 0x26, 0x47, 0xE8, 0x0C, 0x28, 0x38, 0x8B, 0xD2, 0x9C,
        0x15, 0xC9, 0x71, 0x84, 0xF0, 0x3F, 0x31, 0x33, 0x66, 0xF4,
        0xA5, 0xB2, 0xD4, 0xC6, 0x15, 0x4C, 0x30, 0xD9, 0xD1, 0x5C,
        0x3F, 0xCD, 0x01, 0xD7, 0x7C, 0x21, 0xA7, 0x5C, 0xD4, 0x23,
        0xF4, 0xAE, 0x9C, 0x00, 0x7B, 0x88, 0xD7, 0x9C, 0x15, 0x62,
        0x9C, 0xA5, 0xCA, 0xF5, 0x7E, 0x9A, 0x86, 0xED, 0x33, 0xD3,
        0xE5, 0x4B, 0x08, 0xDB, 0x72, 0xE7, 0xA6, 0x63, 0x13, 0x7D,
        0x90, 0x16, 0x7A, 0xC9, 0x7C, 0x45, 0xF3, 0xAF, 0x5A, 0x26,
        0xE3, 0x33, 0xE4, 0xEA, 0x3B, 0x3C, 0x4D, 0x60, 0x56, 0x40,
        0xA3, 0xD5, 0x1D, 0x66, 0x25, 0x35, 0xDB, 0x48, 0x84, 0x22,
        0xD0, 0x86, 0xBE, 0xBA, 0x86, 0xA4, 0x9C, 0x39, 0xBC, 0x42,
        0x74, 0xD1, 0x84, 0x6D, 0xC8, 0xC1, 0xD1, 0x0B, 0xCD, 0xD7,
        0xB4, 0xBD, 0x5C, 0x79, 0xC5, 0xFD, 0x75, 0x08, 0x92, 0x07,
        0x31, 0x17, 0x60, 0xF9, 0x6A, 0xA6, 0x3A, 0x81, 0x57, 0x28,
        0xE1, 0x76, 0xE1, 0x2E, 0xE3, 0x55, 0xE5, 0xD6, 0xF1, 0x52,
        0x9D, 0xD7, 0x0B, 0x8F, 0x0D, 0x98, 0xA1, 0xA4, 0x1A, 0x1F,
        0xA0, 0x95, 0x50, 0x2E, 0x3E, 0x6C, 0xD0, 0xAA, 0xD8, 0x21,
        0xEF, 0x32, 0x7A, 0x44, 0x66, 0x4A, 0x5D, 0x13, 0xF6, 0x43,
        0x32, 0x9B, 0x8B, 0xBF, 0xCA, 0xFE, 0xC5, 0x5D, 0x00, 0x63,
        0x8F, 0x4B, 0x9E, 0x8E, 0xAA, 0x58, 0x93, 0xD2, 0xA9, 0xA1,
        0x9C, 0xEA, 0x29, 0x8D, 0xB8, 0x7E, 0xCA, 0x4B, 0xDE, 0xCF,
        0x08, 0xF3, 0xDD, 0x10, 0x42, 0xA2, 0x25, 0x69, 0x73, 0xB6,
        0x91, 0x3E, 0x7D, 0x05, 0x5C, 0xE2, 0x79, 0xEE, 0xBB, 0xE0,
        0x08, 0xC5, 0x39, 0x6E, 0x1E, 0x86, 0x9C, 0x20, 0x9F, 0x2C,
        0xB9, 0x89, 0x8A, 0x0E, 0xA7, 0xA2, 0x07, 0x54, 0x86, 0x72,
        0xC4, 0x19, 0x85, 0xCD, 0x61, 0x64, 0xEC, 0xEA, 0x6B, 0x70,
        0x86, 0x4A, 0xAC, 0xE2, 0x21, 0xDC, 0xA4, 0xF8, 0x96, 0xF8,
        0x02, 0x8A, 0x80, 0xD4, 0x0E, 0x00, 0x4C, 0x7D, 0xA7, 0xF4,
        0x4A, 0x0E, 0x6A, 0x34, 0xAA, 0x05, 0xBC, 0x6F, 0xF9, 0x3F,
        0x66, 0x50, 0x55, 0xDD, 0xF6, 0x9A, 0x65, 0xC3, 0x38, 0x53,
        0x53, 0xEA, 0x66, 0x6A, 0x34, 0x9E, 0x4F, 0xBA, 0xF1, 0x78,
        0x42, 0x54, 0x0C, 0x28, 0xC9, 0x04, 0x07, 0x97, 0xD3, 0x0F,
        0x03, 0x45, 0x42, 0x2D, 0x9D, 0x87, 0x0D, 0x7A, 0x18, 0x4E,
        0x3F, 0x7B, 0x5F, 0x35, 0x27, 0x13, 0x24, 0xFE, 0x33, 0xF3,
        0x1B, 0x28, 0x14, 0xD2, 0x0A, 0x82, 0x1D, 0xF9, 0x69, 0x26,
        0xD3, 0x59, 0x98, 0xAE, 0x05, 0x77, 0xBC, 0xF2, 0x0A, 0x2C,
        0xAF, 0xB4, 0x14, 0x48, 0x7E, 0x5C, 0x20, 0x08, 0xC3, 0x06,
        0xF0, 0xF4, 0xE0, 0xFA, 0xF1, 0x39, 0xF8, 0x24, 0x91, 0x0A,
        0x6D, 0x95, 0x32, 0xCB, 0x73, 0x83, 0x38, 0x29, 0xBB, 0xDC,
        0x67, 0x82, 0x3D, 0x4B, 0x68, 0x5B, 0xB1, 0xC5, 0xB4, 0x60,
        0x99, 0x6C, 0x22, 0x3B, 0xF8, 0x0D, 0x86, 0xD8, 0xD5, 0x44,
        0xBC, 0x77, 0x38, 0xC8, 0x3C, 0xDF, 0x8B, 0xBE, 0x80, 0xDE,
        0x7F, 0xAA, 0xB3, 0x55, 0x0E, 0xC0, 0xA3, 0xD3, 0x0B, 0x1A,
        0x7D, 0x36, 0xBF, 0x6F, 0x6E, 0xB1, 0xAC, 0x4A, 0xA7, 0x83,
        0x91, 0xA8, 0x36, 0x72, 0xDE, 0x07, 0x1E, 0x8C, 0x8A, 0xE8,
        0xFD, 0x6A, 0xB5, 0x2B, 0x35, 0x5E, 0x23, 0xF0, 0x09, 0x0B,
        0x95, 0xF2, 0x26, 0xBA, 0xBD, 0xB6, 0x75, 0x31, 0x7F, 0x21,
        0xDB, 0x25, 0xA4, 0x2B, 0x3B, 0xCF, 0x76, 0xA6, 0xD0, 0x4D,
        0x7D, 0x3E, 0xE5, 0x86, 0xB3, 0x17, 0x7F, 0xA1, 0x54, 0x11,
        0x9A, 0xDF, 0xA3, 0xD8, 0x47, 0x98, 0x30, 0x21, 0x3F, 0x63,
        0x1A, 0x4D, 0xE0, 0x3B, 0xEF, 0x44, 0x42, 0xD8, 0x08, 0x05,
        0x2B, 0x88, 0x01, 0xEA, 0x8B, 0x88, 0x55, 0x1C, 0x26, 0xD4,
        0xD1, 0x3C, 0xC8, 0xAA, 0x22, 0x10, 0x42, 0x23, 0x0A, 0xEB,
        0xBE, 0xF8, 0xBB, 0x7F, 0x3A, 0x9D, 0x79, 0xAD, 0x28, 0xEF,
        0xE2, 0x47, 0xFD, 0x57, 0x78, 0x8F, 0x62, 0x81, 0xA6, 0xC1,
        0xFA, 0x0B, 0xEA, 0x39, 0x75, 0x4C, 0xE0, 0x11, 0xFC, 0x86,
        0x16, 0xA3, 0x1B, 0xA2, 0xFC, 0x00, 0x55, 0x81, 0x31, 0xAC,
        0x15, 0xC2, 0x9B, 0x9D, 0xB3, 0xB0, 0x51, 0x73, 0x53, 0xCD,
        0xF2, 0xCA, 0x5E, 0x9B, 0x4D, 0xC2, 0xF6, 0xCD, 0x05, 0x87,
        0x15, 0xC6, 0xBE, 0x17, 0x7D, 0x90, 0x33, 0x62, 0xED, 0x31,
        0xE8, 0x46, 0x53, 0x6D, 0x55, 0x06, 0x84, 0x3A, 0x5A, 0x6C,
        0x5B, 0x64, 0xA0, 0x0F, 0x8D, 0xA0, 0xD4, 0x19, 0x9F, 0x64,
        0x3A, 0x9E, 0x74, 0x00, 0x4A, 0xE1, 0x66, 0xFA, 0xDF, 0x90,
        0x00, 0x8A, 0xA4, 0x21, 0x17, 0xF5, 0xE6, 0xEA, 0xDF, 0xDA,
        0x2B, 0xAB, 0x78, 0x69, 0xC7, 0xA5, 0x66, 0x6F, 0x81, 0x2F,
        0xEC, 0x2E, 0x10, 0x2E, 0x42, 0xA6, 0x36, 0x5B, 0x6A, 0x95,
        0xE3, 0x25, 0xCC, 0xC4, 0xE7, 0xDB, 0x8E, 0x90, 0x0C, 0x9A,
        0x2E, 0x8F, 0x6C, 0xF1, 0x08, 0x3B, 0x74, 0x70, 0xAE, 0x28,
        0x4F, 0xAD, 0x82, 0xC7, 0x1B, 0x68, 0x77, 0x5F, 0xD3, 0x97,
        0x7B, 0x39, 0x88, 0x5A, 0x85, 0xC4, 0xB1, 0x9D, 0x03, 0x89,
        0xBD, 0xBC, 0x33, 0xE1, 0xDF, 0x39, 0xF2, 0xE7, 0x05, 0xF7,
        0x9F, 0x60, 0x40, 0xB5, 0x4E, 0xE6, 0xD8, 0xEC, 0x0F, 0xB3,
        0xE4, 0x2C, 0xE0, 0x2E, 0x22, 0xBF, 0x25, 0xE7, 0x05, 0x8D,
        0xAA, 0x4F, 0xBB, 0x68, 0x1A, 0xEB, 0x20, 0x76, 0x20, 0x9D,
        0xD6, 0xDB, 0x4C, 0xE9, 0x8A, 0x02, 0x63, 0xD9, 0x50, 0xBE,
        0xB7, 0x34, 0xC9, 0xC6, 0x1F, 0x48, 0x2F, 0xF8, 0x3A, 0xE7,
        0x4B, 0x84, 0xEA, 0xF5, 0x40, 0x47, 0x8C, 0x6B, 0x37, 0xF3,
        0x64, 0x65, 0xA1, 0x68, 0x68, 0x29, 0x9C, 0x47, 0x71, 0xE7,
        0xA6, 0xD5, 0xCF, 0x6A, 0x0F, 0x81, 0x69, 0xF8, 0x40, 0x98,
        0x0C, 0x63, 0xAA, 0x38, 0xE5, 0xBA, 0x5E, 0x49, 0x7D, 0x85,
        0x31, 0xC7, 0x5D, 0x2D, 0xE8, 0x42, 0x7D, 0x1C, 0xE0, 0xA4,
        0xD0, 0x19, 0x85, 0x96, 0x50, 0x5C, 0x8F, 0x42, 0x6E, 0x7C,
        0x59, 0xB7, 0x09, 0xC9, 0xD6, 0x3D, 0xFF, 0x1C, 0x95, 0xFD,
        0xD5, 0x4A, 0xE0, 0x9B, 0xD9, 0x7B, 0x6C, 0x19, 0xE2, 0xB2,
        0x27, 0x46, 0x67, 0x30, 0x61, 0x48, 0x1A, 0xD9, 0x65, 0x1B,
        0x3E, 0xA9, 0xB4, 0x7C, 0xB6, 0x30, 0x58, 0xA5, 0x5D, 0x2D,
        0xA7, 0x5C, 0xE4, 0x53, 0xB2, 0xAF, 0x84, 0x03, 0xFE, 0xCA,
        0x02, 0x90, 0x8F, 0xCF, 0x74, 0x1D, 0x73, 0x0E, 0xB4, 0xCD,
        0x99, 0x5D, 0x2D, 0x93, 0xBE, 0x07, 0xA6, 0xBC, 0x3A, 0x86,
        0x23, 0x56, 0x17, 0xE8, 0x46, 0x0E, 0xF3, 0xEC, 0x7D, 0x14,
        0x24, 0x25, 0x5F, 0x4C, 0xD2, 0xA2, 0x91, 0xA1, 0x25, 0xD7,
        0x7F, 0xC0, 0x19, 0xED, 0x19, 0xD0, 0xC3, 0x0C, 0x74, 0x99,
        0xF0, 0xA7, 0xEB, 0x9E, 0x5B, 0xBB, 0x38, 0x8C, 0xB4, 0x3F,
        0x28, 0xB7, 0x4C, 0xEA, 0x33, 0xC0, 0x8A, 0x45, 0xA3, 0x23,
        0xF7, 0xAB, 0x6A, 0xAA, 0x0A, 0x2F, 0x38, 0xAD, 0x9C, 0x47,
        0x77, 0x56, 0xDB, 0xB6, 0x04, 0xFC, 0xD9, 0x10, 0xEB, 0xB6,
        0x91, 0x61, 0x46, 0x1A, 0x00, 0xBB, 0xC5, 0x8B, 0xC5, 0x48,
        0xD7, 0x51, 0xDF, 0x1E, 0x4D, 0xA1, 0x05, 0x79, 0x99, 0x81,
        0xB2, 0xF5, 0xD9, 0x36, 0x81, 0x07, 0x50, 0xAF, 0x23, 0x48,
        0xA8, 0x1B, 0x2F, 0x57, 0xCA, 0x90, 0xE1, 0x01, 0x56, 0x25,
        0xB6, 0xB6, 0x7E, 0x5D, 0x0D, 0xE4, 0xF6, 0xE4, 0x84, 0x6F,
        0x4D, 0x8A, 0x9C, 0x0B
    };
    static unsigned char dhg_8192[] = {
        0x02
    };
    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (dh == NULL)
        return NULL;
    p = BN_bin2bn(dhp_8192, sizeof(dhp_8192), NULL);
    g = BN_bin2bn(dhg_8192, sizeof(dhg_8192), NULL);
    if (p == NULL || g == NULL
            || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }
    return dh;
}
-----BEGIN DH PARAMETERS-----
MIIECAKCBAEAjD0XGiMuaD+LwvsmR+gMKDiL0pwVyXGE8D8xM2b0pbLUxhVMMNnR
XD/NAdd8Iadc1CP0rpwAe4jXnBVinKXK9X6ahu0z0+VLCNty56ZjE32QFnrJfEXz
r1om4zPk6js8TWBWQKPVHWYlNdtIhCLQhr66hqScObxCdNGEbcjB0QvN17S9XHnF
/XUIkgcxF2D5aqY6gVco4XbhLuNV5dbxUp3XC48NmKGkGh+glVAuPmzQqtgh7zJ6
RGZKXRP2QzKbi7/K/sVdAGOPS56OqliT0qmhnOopjbh+ykvezwjz3RBCoiVpc7aR
Pn0FXOJ57rvgCMU5bh6GnCCfLLmJig6nogdUhnLEGYXNYWTs6mtwhkqs4iHcpPiW
+AKKgNQOAEx9p/RKDmo0qgW8b/k/ZlBV3faaZcM4U1PqZmo0nk+68XhCVAwoyQQH
l9MPA0VCLZ2HDXoYTj97XzUnEyT+M/MbKBTSCoId+Wkm01mYrgV3vPIKLK+0FEh+
XCAIwwbw9OD68Tn4JJEKbZUyy3ODOCm73GeCPUtoW7HFtGCZbCI7+A2G2NVEvHc4
yDzfi76A3n+qs1UOwKPTCxp9Nr9vbrGsSqeDkag2ct4HHoyK6P1qtSs1XiPwCQuV
8ia6vbZ1MX8h2yWkKzvPdqbQTX0+5YazF3+hVBGa36PYR5gwIT9jGk3gO+9EQtgI
BSuIAeqLiFUcJtTRPMiqIhBCIwrrvvi7fzqdea0o7+JH/Vd4j2KBpsH6C+o5dUzg
EfyGFqMbovwAVYExrBXCm52zsFFzU83yyl6bTcL2zQWHFca+F32QM2LtMehGU21V
BoQ6WmxbZKAPjaDUGZ9kOp50AErhZvrfkACKpCEX9ebq39orq3hpx6Vmb4Ev7C4Q
LkKmNltqleMlzMTn246QDJouj2zxCDt0cK4oT62Cxxtod1/Tl3s5iFqFxLGdA4m9
vDPh3zny5wX3n2BAtU7m2OwPs+Qs4C4ivyXnBY2qT7toGusgdiCd1ttM6YoCY9lQ
vrc0ycYfSC/4OudLhOr1QEeMazfzZGWhaGgpnEdx56bVz2oPgWn4QJgMY6o45bpe
SX2FMcddLehCfRzgpNAZhZZQXI9CbnxZtwnJ1j3/HJX91Urgm9l7bBnisidGZzBh
SBrZZRs+qbR8tjBYpV0tp1zkU7KvhAP+ygKQj890HXMOtM2ZXS2TvgemvDqGI1YX
6EYO8+x9FCQlX0zSopGhJdd/wBntGdDDDHSZ8Kfrnlu7OIy0Pyi3TOozwIpFoyP3
q2qqCi84rZxHd1bbtgT82RDrtpFhRhoAu8WLxUjXUd8eTaEFeZmBsvXZNoEHUK8j
SKgbL1fKkOEBViW2tn5dDeT25IRvTYqcCwIBAg==
-----END DH PARAMETERS-----
