#include <windows.h>
#include <stdio.h>
#include <Winternl.h >
#include <stdlib.h>
#pragma comment(lib ,"ntdll.lib")
typedef struct _SYSTEM_BASIC_INFORMATION2
{
	ULONG Reserved;
	ULONG TimerResolution;
	ULONG PageSize;
	ULONG NumberOfPhysicalPages;
	ULONG LowestPhysicalPageNumber;
	ULONG HighestPhysicalPageNumber;
	ULONG AllocationGranularity;
	ULONG_PTR MinimumUserModeAddress;
	ULONG_PTR MaximumUserModeAddress;
	ULONG_PTR ActiveProcessorsAffinityMask;
	CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION2, * PSYSTEM_BASIC_INFORMATION2;
int main()
{
	ULONG whyme=0;
	SYSTEM_BASIC_INFORMATION2 sbi;

	NTSTATUS status = NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(SYSTEM_BASIC_INFORMATION2), &whyme);
	printf("Size : 0x%x Status: 0x%x\n", whyme,status);

	printf("ActiveProcessorsAffinityMask : 0x%x\n", sbi.ActiveProcessorsAffinityMask);
	printf("AllocationGranularity : 0x%x\n", sbi.AllocationGranularity);
	printf("HighestPhysicalPageNumber : 0x%x\n", sbi.HighestPhysicalPageNumber);
	printf("LowestPhysicalPageNumber : 0x%x\n", sbi.LowestPhysicalPageNumber);
	printf("MaximumUserModeAddress : 0x%x\n", sbi.MaximumUserModeAddress);
	printf("MinimumUserModeAddress : 0x%x\n", sbi.MinimumUserModeAddress);
	printf("NumberOfPhysicalPages : 0x%x\n", sbi.NumberOfPhysicalPages);
	printf("NumberOfProcessors : 0x%x\n", sbi.NumberOfProcessors);
	printf("PageSize : 0x%x\n", sbi.PageSize);
	printf("TimerResolution : 0x%x\n", sbi.TimerResolution);

}
