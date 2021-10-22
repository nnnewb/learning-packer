#include <Windows.h>
#include <memory.h>
#include <stdlib.h>
#include <winnt.h>

int main(void) {
  MessageBoxA(NULL, "Hello world!", "MSGBOX", MB_OK);
  return 0;
}
