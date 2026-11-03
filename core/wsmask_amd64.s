//go:build linux && amd64

#include "textflag.h"

TEXT ·maskXORAVX2(SB), NOSPLIT, $0-24
	MOVQ p+0(FP), SI
	MOVQ n+8(FP), CX
	MOVQ mask+16(FP), AX
	MOVQ AX, X0
	VPBROADCASTQ X0, Y0

loop128:
	CMPQ CX, $128
	JB   loop32
	VPXOR   (SI), Y0, Y1
	VPXOR   32(SI), Y0, Y2
	VPXOR   64(SI), Y0, Y3
	VPXOR   96(SI), Y0, Y4
	VMOVDQU Y1, (SI)
	VMOVDQU Y2, 32(SI)
	VMOVDQU Y3, 64(SI)
	VMOVDQU Y4, 96(SI)
	ADDQ    $128, SI
	SUBQ    $128, CX
	JMP     loop128

loop32:
	CMPQ CX, $32
	JB   done
	VPXOR   (SI), Y0, Y1
	VMOVDQU Y1, (SI)
	ADDQ    $32, SI
	SUBQ    $32, CX
	JMP     loop32

done:
	VZEROUPPER
	RET

TEXT ·asciiPrefixAVX2(SB), NOSPLIT, $0-24
	MOVQ p+0(FP), SI
	MOVQ n+8(FP), CX
	XORQ AX, AX

ascii128:
	MOVQ CX, DX
	SUBQ AX, DX
	CMPQ DX, $128
	JB   ascii32
	VMOVDQU (SI)(AX*1), Y0
	VPOR    32(SI)(AX*1), Y0, Y0
	VPOR    64(SI)(AX*1), Y0, Y0
	VPOR    96(SI)(AX*1), Y0, Y0
	VPMOVMSKB Y0, DX
	TESTL   DX, DX
	JNZ     ascii32
	ADDQ    $128, AX
	JMP     ascii128

ascii32:
	CMPQ AX, CX
	JAE  asciidone
	VMOVDQU (SI)(AX*1), Y0
	VPMOVMSKB Y0, DX
	TESTL   DX, DX
	JNZ     asciidone
	ADDQ    $32, AX
	JMP     ascii32

asciidone:
	VZEROUPPER
	MOVQ AX, ret+16(FP)
	RET
