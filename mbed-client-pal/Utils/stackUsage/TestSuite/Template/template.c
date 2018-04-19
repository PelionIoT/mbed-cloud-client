int stackUsage_Template()
{
	char* stackArr = NULL;
	int i = 0;
	int stackUsageCounter = 0;
	bool detectChange = false;
	char borderArr[BORDER_ARRAY_SIZE]; //Used to mark the border of a stack frame.
	for(i=0; i < BORDER_ARRAY_SIZE; ++i)
	{
		borderArr[i] = INIT_VALUE;
	}
	stackArr = paintStack();
	Template_Func();
	// The size of the second array is: 3*STACK_UNIT_SIZE.
	// so we need to run over the array to detect the first changed byte.
	// once we detect this byte, we can calculate the maximum stack usage.
	for (i = 0 ; i < STACK_UNIT_NUM*STACK_UNIT_SIZE && !detectChange; ++i)
	{
		if(stackArr[i] != ((memPattern[i%PATTERN_SIZE]) ^ (i%MAX_CHAR_VALUE)))
		{
			detectChange = true;
		}
	}
	stackUsageCounter = STACK_UNIT_NUM*STACK_UNIT_SIZE - i;
	stackArr = stackArr + STACK_UNIT_NUM * STACK_UNIT_SIZE;
	for (; stackArr != borderArr; ++stackArr)
	{
		++stackUsageCounter;
	}
	return stackUsageCounter;
}
