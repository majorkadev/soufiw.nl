void cpuid_emulator(PCONTEXT ctx)
{
    DWORD leaf = ctx->Eax;
    DWORD subleaf = 0; ctx->Ecx;

    if (!leaf && !subleaf)
    {
        ctx->Eax = 0x10;
        ctx->Ebx = 0x68747541;
        ctx->Ecx = 0x444D4163;
        ctx->Edx = 0x69746E65;
    }
    else if (leaf == 1 && !subleaf)
    {
        ctx->Eax = 0x0A60F12;
        ctx->Ebx = 0x100800;
        ctx->Ecx = 0x7ED8320B;
        ctx->Edx = 0x178BFBFF;
    }
    else if (leaf == 2 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 3 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 4 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 4 && subleaf == 1)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 4 && subleaf == 2)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 4 && subleaf == 3)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 4 && subleaf == 4)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 5 && !subleaf)
    {
        ctx->Eax = 0x40;
        ctx->Ebx = 0x40;
        ctx->Ecx = 0x3;
        ctx->Edx = 0x11;
    }
    else if (leaf == 6 && !subleaf)
    {
        ctx->Eax = 0x4;
        ctx->Ebx = 0x0;
        ctx->Ecx = 0x1;
        ctx->Edx = 0x0;
    }
    else if (leaf == 7 && !subleaf)
    {
        ctx->Eax = 0x1;
        ctx->Ebx = 0x0F1BF97A9;
        ctx->Ecx = 0x405FCE;
        ctx->Edx = 0x10000010;
    }
    else if (leaf == 7 && subleaf == 1)
    {
        ctx->Eax = 20;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 7 && subleaf == 2)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 7 && subleaf == 3)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 7 && subleaf == 4)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 8 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 9 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 10 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 11 && !subleaf)
    {
        ctx->Eax = 0x1;
        ctx->Ebx = 0x2;
        ctx->Ecx = 0x100;
        ctx->Edx = 0x6;
    }
    else if (leaf == 12 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 13 && !subleaf)
    {
        ctx->Eax = 0x2E7;
        ctx->Ebx = 0x980;
        ctx->Ecx = 0x988;
        ctx->Edx = 0x0;
    }
    else if (leaf == 14 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 15 && !subleaf)
    {
        ctx->Eax = 0x0;
        ctx->Ebx = 0x0FF;
        ctx->Ecx = 0x0;
        ctx->Edx = 0x2;
    }
    else if (leaf == 16 && !subleaf)
    {
        ctx->Eax = 0x0;
        ctx->Ebx = 0x2;
        ctx->Ecx = 0x0;
        ctx->Edx = 0x0;
    }
    else if (leaf == 0x80000000 && !subleaf)
    {
        ctx->Eax = 0x80000028;
        ctx->Ebx = 0x68747541;
        ctx->Ecx = 0x444D4163;
        ctx->Edx = 0x69746E65;
    }
    else if (leaf == 0x80000001 && !subleaf)
    {
        ctx->Eax = 0x0A60F12;
        ctx->Ebx = 0x0;
        ctx->Ecx = 0x75C237FF;
        ctx->Edx = 0x2FD3FBFF;
    }
    else if (leaf == 0x80000002 && !subleaf)
    {
        ctx->Eax = 0x20444D41;
        ctx->Ebx = 0x657A7952;
        ctx->Ecx = 0x2037206E;
        ctx->Edx = 0x30303737;
    }
    else if (leaf == 0x80000003 && !subleaf)
    {
        ctx->Eax = 0x2D382058;
        ctx->Ebx = 0x65726F43;
        ctx->Ecx = 0x6F725020;
        ctx->Edx = 0x73736563;
    }
    else if (leaf == 0x80000004 && !subleaf)
    {
        ctx->Eax = 0x2020726F;
        ctx->Ebx = 0x20202020;
        ctx->Ecx = 0x20202020;
        ctx->Edx = 0x202020;
    }
    else if (leaf == 0x80000005 && !subleaf)
    {
        ctx->Eax = 0x0FF48FF40;
        ctx->Ebx = 0x0FF48FF40;
        ctx->Ecx = 0x20080140;
        ctx->Edx = 0x20080140;
    }
    else if (leaf == 0x80000006 && !subleaf)
    {
        ctx->Eax = 0x5C002200;
        ctx->Ebx = 0x6C004200;
        ctx->Ecx = 0x4006140;
        ctx->Edx = 0x1009140;
    }
    else if (leaf == 0x80000007 && !subleaf)
    {
        ctx->Eax = 0x0;
        ctx->Ebx = 0x3B;
        ctx->Ecx = 0x0;
        ctx->Edx = 0x6799;
    }
    else if (leaf == 0x80000008 && !subleaf)
    {
        ctx->Eax = 0x3030;
        ctx->Ebx = 0x791EF257;
        ctx->Ecx = 0x400F;
        ctx->Edx = 0x10000;
    }
    else if (leaf == 0x80000009 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 0x8000000A && !subleaf)
    {
        ctx->Eax = 0x1;
        ctx->Ebx = 0x8000;
        ctx->Ecx = 0x0;
        ctx->Edx = 0x1EBFBCFF;
    }
    else if (leaf == 0x8000000B && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 0x8000000C && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 0x8000000D && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 0x8000000E && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 0x8000000F && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 0x80000010 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 0x80000011 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 0x80000012 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 0x80000013 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 0x80000014 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 0x80000015 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 0x80000016 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 0x80000017 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 0x80000018 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 0x80000019 && !subleaf)
    {
        ctx->Eax = 0x0F048F040;
        ctx->Ebx = 0x0F0400000;
        ctx->Ecx = 0x0;
        ctx->Edx = 0x0;
    }
    else if (leaf == 0x8000001A && !subleaf)
    {
        ctx->Eax = 0x6;
        ctx->Ebx = 0x0;
        ctx->Ecx = 0x0;
        ctx->Edx = 0x0;
    }
    else if (leaf == 0x8000001B && !subleaf)
    {
        ctx->Eax = 0x0BFF;
        ctx->Ebx = 0x0;
        ctx->Ecx = 0x0;
        ctx->Edx = 0x0;
    }
    else if (leaf == 0x8000001C && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 0x8000001D && !subleaf)
    {
        ctx->Eax = 0x4121;
        ctx->Ebx = 0x1C0003F;
        ctx->Ecx = 0x3F;
        ctx->Edx = 0x0;
    }
    else if (leaf == 0x8000001E && !subleaf)
    {
        ctx->Eax = 0x0C;
        ctx->Ebx = 0x106;
        ctx->Ecx = 0x0;
        ctx->Edx = 0x0;
    }
    else if (leaf == 0x8000001F && !subleaf)
    {
        ctx->Eax = 0x1;
        ctx->Ebx = 0x0B3;
        ctx->Ecx = 0x0;
        ctx->Edx = 0x0;
    }
    else if (leaf == 0x80000020 && !subleaf)
    {
        ctx->Eax = 0x0;
        ctx->Ebx = 0x1E;
        ctx->Ecx = 0x0;
        ctx->Edx = 0x0;
    }
    else if (leaf == 0x80000021 && !subleaf)
    {
        ctx->Eax = 0x62FCF;
        ctx->Ebx = 0x15C;
        ctx->Ecx = 0x0;
        ctx->Edx = 0x0;
    }
    else if (leaf == 0x80000022 && !subleaf)
    {
        ctx->Eax = 0x7;
        ctx->Ebx = 0x84106;
        ctx->Ecx = 0x3;
        ctx->Edx = 0x0;
    }
    else if (leaf == 0x80000023 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 0x80000024 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 0x80000025 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 0x80000026 && !subleaf)
    {
        ctx->Eax = 0x1;
        ctx->Ebx = 0x2;
        ctx->Ecx = 0x100;
        ctx->Edx = 0x0C;
    }
    else if (leaf == 0x80000027 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    }
    else if (leaf == 0x80000028 && !subleaf)
    {
        ctx->Eax = 0;
        ctx->Ebx = 0;
        ctx->Ecx = 0;
        ctx->Edx = 0;
    };
};