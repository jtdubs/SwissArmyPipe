#include <windows.h>
#include <stdio.h>

void TestSyncMessage();
DWORD WINAPI SyncMessage_ServerThread(LPVOID);
DWORD WINAPI SyncMessage_ClientThread(LPVOID);

void TestGetOverlappedResult();
DWORD WINAPI GetOverlappedResult_ServerThread(LPVOID);
DWORD WINAPI GetOverlappedResult_ClientThread(LPVOID);


HANDLE semaphore, server, client;

int main()
{
	Sleep(2000);
	TestSyncMessage();
	Sleep(2000);
	TestGetOverlappedResult();
	Sleep(2000);

	return 0;
}

void TestSyncMessage()
{
	printf("Testing Native Sync Message...\n");

	semaphore = CreateSemaphore(NULL, 0, 2, NULL);
	
	server = CreateNamedPipe(L"\\\\.\\pipe\\native_sync_message", PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE, 1, 1024, 1024, 1000, NULL);
	client = CreateFile(L"\\\\.\\pipe\\native_sync_message", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	HANDLE serverThread = CreateThread(NULL, 1024, &SyncMessage_ServerThread, NULL, 0, NULL);
	HANDLE clientThread = CreateThread(NULL, 1024, &SyncMessage_ClientThread, NULL, 0, NULL);

	WaitForSingleObject(semaphore, INFINITE);
	WaitForSingleObject(semaphore, INFINITE);

	CloseHandle(server);
	CloseHandle(client);
	CloseHandle(semaphore);

	printf("Done.\n");
}

DWORD WINAPI SyncMessage_ServerThread(LPVOID lpParameter)
{
	DWORD bytesWritten, bytesRead;
	char buffer[128];

	for (int i = 0; i < 10; i++)
	{
		WriteFile(server, "sample request\r\n", 16, &bytesWritten, NULL);
		ReadFile(server, buffer, 128, &bytesRead, NULL);
		if (strncmp(buffer, "sample response\r\n", 17) != 0)
			exit(1);
	}

	ReleaseSemaphore(semaphore, 1, NULL);
	return 0;
}

DWORD WINAPI SyncMessage_ClientThread(LPVOID lpParameter)
{
	DWORD bytesWritten, bytesRead;
	char buffer[128];

	for (int i = 0; i < 10; i++)
	{
		ReadFile(client, buffer, 128, &bytesRead, NULL);
		if (strncmp(buffer, "sample request\r\n", 16) != 0)
			exit(1);
		WriteFile(client, "sample response\r\n", 17, &bytesWritten, NULL);
	}

	ReleaseSemaphore(semaphore, 1, NULL);
	return 0;
}

void TestGetOverlappedResult()
{
	printf("Testing Native GetOverlappedResult...\n");

	semaphore = CreateSemaphore(NULL, 0, 2, NULL);

	server = CreateNamedPipe(L"\\\\.\\pipe\\native_getoverlappedresult", PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE | PIPE_WAIT, 1, 1024, 1024, 1000, NULL);
	client = CreateFile(L"\\\\.\\pipe\\native_getoverlappedresult", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

	HANDLE serverThread = CreateThread(NULL, 1024, &GetOverlappedResult_ServerThread, NULL, 0, NULL);
	HANDLE clientThread = CreateThread(NULL, 1024, &GetOverlappedResult_ClientThread, NULL, 0, NULL);

	WaitForSingleObject(semaphore, INFINITE);
	WaitForSingleObject(semaphore, INFINITE);

	CloseHandle(server);
	CloseHandle(client);
	CloseHandle(semaphore);

	printf("Done.\n");
}

DWORD WINAPI GetOverlappedResult_ServerThread(LPVOID lpParameter)
{
	DWORD bytesWritten, bytesRead;
	char buffer[128];

	OVERLAPPED overlapped = { 0 };

	for (int i = 0; i < 10; i++)
	{
		WriteFile(server, "sample request\r\n", 16, NULL, &overlapped);
		GetOverlappedResult(server, &overlapped, &bytesWritten, TRUE);

		ReadFile(server, buffer, 128, NULL, &overlapped);
		GetOverlappedResult(server, &overlapped, &bytesRead, TRUE);

		if (strncmp(buffer, "sample response\r\n", 17) != 0)
			exit(1);
	}

	ReleaseSemaphore(semaphore, 1, NULL);
	return 0;
}

DWORD WINAPI GetOverlappedResult_ClientThread(LPVOID lpParameter)
{
	DWORD bytesWritten, bytesRead;
	char buffer[128];

	OVERLAPPED overlapped = { 0 };

	for (int i = 0; i < 10; i++)
	{
		ReadFile(client, buffer, 128, NULL, &overlapped);
		GetOverlappedResult(client, &overlapped, &bytesRead, TRUE);

		if (strncmp(buffer, "sample request\r\n", 16) != 0)
			exit(1);

		WriteFile(client, "sample response\r\n", 17, NULL, &overlapped);
		GetOverlappedResult(client, &overlapped, &bytesWritten, TRUE);
	}

	ReleaseSemaphore(semaphore, 1, NULL);
	return 0;
}

