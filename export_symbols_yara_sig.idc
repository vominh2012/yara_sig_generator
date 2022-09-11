// based on https://gist.github.com/hax0kartik/e358ce447a4537bcef534aa8de84817c
#include <idc.idc>

static FuncDump(f, start)
{
	auto MIN_CUT_OFF = 20; // bytes
	auto MAX_CUT_OFF = 256; // bytes
	
    auto ea, str, teststr, ea_end, bytes;

    ea = start;

    while( ea != BADADDR )
    {
        str = GetFunctionName(ea);
		
		auto name = Demangle(str,  GetLongPrm(INF_SHORT_DN));
		auto safe_name = name;
		
		bytes = 0;
		ea_end = FindFuncEnd(ea);
		if (ea_end != BADADDR) 
		{
			bytes = ea_end - ea;
		}
		
        if(bytes >= MIN_CUT_OFF && bytes <= MAX_CUT_OFF && safe_name != 0)
        {
            // Skip functions whose name is the generic sub_XXX()
            teststr = sprintf("sub_%X", ea);
            if( teststr != str )
            {
                fprintf(f, "0x%X,%d,%s\n", ea, bytes, safe_name);
            }
        }

        ea = NextFunction(ea);
    }
}

static main() 
{
    auto current = GetInputFile();
    current = AskFile(-1, current, "Where should I write the symbols to?");
    if(current == 0)
    {
        return -1;
    }
    auto f = fopen(current, "wb");
    Message("FuncDump: Start\n");

    FuncDump(f, 0x400000);
    fclose(f);
    Message("FuncDump: Done\n");
}
