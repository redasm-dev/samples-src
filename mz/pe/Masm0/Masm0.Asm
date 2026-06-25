.386
.model flat, stdcall  ;32 bit memory model
option casemap :none  ;case sensitive

include Masm0.inc

.code

start:

	invoke GetModuleHandle,NULL
	mov		hInstance,eax

	invoke DialogBoxParam,hInstance,IDD_MAINFORM,NULL,addr DlgProc,NULL
	invoke ExitProcess,0

;########################################################################

DlgProc proc hWin:HWND,uMsg:UINT,wParam:WPARAM,lParam:LPARAM

	mov	eax,uMsg
	.if eax==WM_CLOSE
		invoke EndDialog,hWin,0
	.else
		mov		eax,FALSE
		ret
	.endif
	mov		eax,TRUE
	ret

DlgProc endp

end start
