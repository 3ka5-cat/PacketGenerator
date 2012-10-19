#include "debug.h"

HANDLE m_hDbgFile = NULL, m_hDbgFileMutex = NULL;
/*
//--------------------------------------------------------------------------------------
BOOL DbgInit(char *lpszDbgLogPath)
{
    m_hDbgFile = NULL;
    m_hDbgFileMutex = NULL;
    
    if (m_hDbgFileMutex = CreateMutexA(NULL, FALSE, DBG_MUTEX_NAME))
    {
        if ((m_hDbgFile = CreateFileA(
            lpszDbgLogPath, 
            GENERIC_READ | GENERIC_WRITE, 
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, 
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL)) != INVALID_HANDLE_VALUE)
        {
            // OK
            SetFilePointer(m_hDbgFile, 0, NULL, FILE_END);
            return TRUE;
        }
        else
        {                
            DbgMsg(__FILE__, __LINE__, "CreateFile() ERROR %d\n", GetLastError());
        }

        CloseHandle(m_hDbgFileMutex);
        
        m_hDbgFile = NULL;
        m_hDbgFileMutex = NULL;
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "CreateMutex() ERROR %d\n", GetLastError());
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
void LogMsg(char *lpszFile, int iLine, char *lpszMsg, ...)
{
    va_list mylist;
    va_start(mylist, lpszMsg);

    int len = _vscprintf(lpszMsg, mylist) + 0x100;

    char *lpszBuff = (char *)M_ALLOC(len);
    if (lpszBuff == NULL)
    {
        va_end(mylist);
        return;
    }

    char *lpszOutBuff = (char *)M_ALLOC(len);
    if (lpszOutBuff == NULL)
    {
        M_FREE(lpszBuff);
        va_end(mylist);
        return;
    }

    vsprintf_s(lpszBuff, len, lpszMsg, mylist);	
    va_end(mylist);

    sprintf_s(lpszOutBuff, len, "%s(%d) : %s", lpszFile, iLine, lpszBuff);	

    HANDLE hStd = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStd != INVALID_HANDLE_VALUE)
    {
        DWORD dwWritten = 0;
        WriteFile(hStd, lpszBuff, strlen(lpszBuff), &dwWritten, NULL);
    }

    if (m_hDbgFile && m_hDbgFileMutex)
    {
        sprintf_s(lpszOutBuff, len, "%s", lpszBuff);	
        WaitForSingleObject(m_hDbgFileMutex, INFINITE);

        DWORD dwWritten;
        SetFilePointer(m_hDbgFile, 0, NULL, FILE_END);
        WriteFile(m_hDbgFile, lpszOutBuff, strlen(lpszOutBuff), &dwWritten, NULL);

        ReleaseMutex(m_hDbgFileMutex);
    }

    M_FREE(lpszBuff);
    M_FREE(lpszOutBuff);
}
*/
//--------------------------------------------------------------------------------------
#ifdef DBG
//--------------------------------------------------------------------------------------
void DbgMsg(char *lpszFile, int iLine, char *lpszMsg, ...)
{
    va_list mylist;
    va_start(mylist, lpszMsg);

    int len = _vscprintf(lpszMsg, mylist) + 0x100;
    
    char *lpszBuff = (char *)M_ALLOC(len);
    if (lpszBuff == NULL)
    {
        va_end(mylist);
        return;
    }

    char *lpszOutBuff = (char *)M_ALLOC(len);
    if (lpszOutBuff == NULL)
    {
        M_FREE(lpszBuff);
        va_end(mylist);
        return;
    }
    
    vsprintf_s(lpszBuff, len, lpszMsg, mylist);	
    va_end(mylist);

    sprintf_s(lpszOutBuff, len, "%s(%d) : %s", lpszFile, iLine, lpszBuff);	

    OutputDebugString(lpszOutBuff);
    
    HANDLE hStd = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStd != INVALID_HANDLE_VALUE)
    {
        DWORD dwWritten = 0;
        WriteFile(hStd, lpszBuff, strlen(lpszBuff), &dwWritten, NULL);
    }

    if (m_hDbgFile && m_hDbgFileMutex)
    {
        sprintf_s(lpszOutBuff, len, "%s", lpszBuff);	
        WaitForSingleObject(m_hDbgFileMutex, INFINITE);

        DWORD dwWritten;
        SetFilePointer(m_hDbgFile, 0, NULL, FILE_END);
        WriteFile(m_hDbgFile, lpszOutBuff, strlen(lpszOutBuff), &dwWritten, NULL);

        ReleaseMutex(m_hDbgFileMutex);
    }

    M_FREE(lpszBuff);
    M_FREE(lpszOutBuff);
}
//--------------------------------------------------------------------------------------
void DbgHexdump(PUCHAR Data, DWORD dwLength) 
{
    DWORD dp = 0, p = 0;
    const char trans[] =
        "................................ !\"#$%&'()*+,-./0123456789"
        ":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
        "nopqrstuvwxyz{|}~...................................."
        "....................................................."
        "........................................";

    char szBuff[0x100], szChar[10];
    ZeroMemory(szBuff, sizeof(szBuff));

    for (dp = 1; dp <= dwLength; dp++)  
    {
        sprintf_s(szChar, sizeof(szChar), "%02x ", Data[dp-1]);
        strcat_s(szBuff, sizeof(szBuff), szChar);

        if ((dp % 8) == 0)
        {
            strcat_s(szBuff, sizeof(szBuff), " ");
        }

        if ((dp % 16) == 0) 
        {
            strcat_s(szBuff, sizeof(szBuff), "| ");
            p = dp;

            for (dp -= 16; dp < p; dp++)
            {
                sprintf_s(szChar, sizeof(szChar), "%c", trans[Data[dp]]);
                strcat_s(szBuff, sizeof(szBuff), szChar);
            }

            DbgMsg(__FILE__, __LINE__, "%.8x: %s\r\n", dp - 16, szBuff);
            ZeroMemory(szBuff, sizeof(szBuff));
        }
    }

    if ((dwLength % 16) != 0) 
    {
        p = dp = 16 - (dwLength % 16);

        for (dp = p; dp > 0; dp--) 
        {
            strcat_s(szBuff, sizeof(szBuff), "   ");

            if (((dp % 8) == 0) && (p != 8))
            {
                strcat_s(szBuff, sizeof(szBuff), " ");
            }
        }

        strcat_s(szBuff, sizeof(szBuff), " | ");
        for (dp = (dwLength - (16 - p)); dp < dwLength; dp++)
        {
            sprintf_s(szChar, sizeof(szChar), "%c", trans[Data[dp]]);
            strcat_s(szBuff, sizeof(szBuff), szChar);
        }

        DbgMsg(__FILE__, __LINE__, "%.8x: %s\r\n", dwLength - (dwLength % 16), szBuff);
    }
}
//--------------------------------------------------------------------------------------
#endif // DBG
//--------------------------------------------------------------------------------------
// EoF
