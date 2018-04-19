# This script responsible to generate C files.
# The generated C files will create a TestSuite
# for the Stack Usage analyzer.
import os
import shutil


SCRIPTDIR = os.path.dirname(os.path.realpath(__file__))
TEMPLATEFILE = os.path.join(SCRIPTDIR, 'Template', 'template.c')
TESTSDIR = os.path.join(SCRIPTDIR, 'Tests')
function_pointer_list = []
STACK_UNIT_SIZE = 1024
STACK_UNIT_NUM = 3


def generate_functions(filename, includes, mainfunction, variables, targetcall):
    generated = open(os.path.join(TESTSDIR, filename+'.c'), "a")
    generated_header = open(os.path.join(TESTSDIR, filename+'.h'), "a")
    template = open(TEMPLATEFILE, "r")
    main_added = False
    vars_added = False

    # insert includes if exist
    if len(includes) != 0:
        for inc in includes.split(';'):
            generated.write('#include \"' + inc + '\"\n')

    # insert test main function
    for line in template:
        if main_added == True and vars_added == False:
            if line.strip() == "{":
                continue
            # insert variables if exist
            if len(variables) != 0:
                for var in variables.split(';'):
                    if len(var.strip(' ')) == 0:
                        continue
                    generated.write("\t"+var.strip(' ')+";\n")
            generated.write(line)
            vars_added = True
            continue

        if line.strip() == "int stackUsage_Template()":
            generated_header.write("int "+mainfunction + "();\n")
            generated.write("int "+mainfunction + "()\n{\n")
            main_added = True
            if mainfunction in function_pointer_list:
                print "Error! This function already exist in the functions vector\n"
                raise Exception('This function: "'+ mainfunction + '" is already exist in the functions vector')
            function_pointer_list.append(mainfunction)
        elif line.strip() == "Template_Func();":
            generated.write("\t"+targetcall+"\n")

        else:
            generated.write(line)
    generated.write('/***********************************************************************/\n')
    generated.write("\n\n")
    generated.write('/***********************************************************************/\n')
    generated.close()
    generated_header.close()
    template.close()


def generate_new_source_files(filename):
    if os.path.exists(TESTSDIR):
        shutil.rmtree(TESTSDIR)

    os.mkdir(TESTSDIR)

    generated_c = open(os.path.join(TESTSDIR, filename+'.c'), "w")
    generated_h = open(os.path.join(TESTSDIR, filename+'.h'), "w")

    generated_c.write('/* This file was generated automatically */\n')
    generated_c.write("#include \""+filename+".h\"\n")
    generated_c.write("\n\n")
    generated_c.close()

    generated_h.write('/**********************************************************************\n')
    generated_h.write('* This file was generated automatically and it describes the generated\n')
    generated_h.write('* Source file "'+filename+'.c" which contains stack usage test functions\n')
    generated_h.write('* for the listed functions in the "TargetFunction.txt" file.\n')
    generated_h.write('* Please do NOT edit these files (header and source) for requests please\n')
    generated_h.write('* send an email to PAL team leader: Alex.Volinski@arm.com \n')
    generated_h.write('**********************************************************************/\n\n')
    generated_h.write("#ifndef _FUNCTIONS_VECTOR_H_\n")
    generated_h.write("#define _FUNCTIONS_VECTOR_H_\n")
    generated_h.write("#include <stdlib.h>\n")
    generated_h.write("#include <stdio.h>\n")
    generated_h.write("#include <stdbool.h>\n")
    generated_h.write("#define STACK_UNIT_SIZE "+ str(STACK_UNIT_SIZE) +"\n")
    generated_h.write("#define STACK_UNIT_NUM "+ str(STACK_UNIT_NUM) +"\n")
    generated_h.write("char* paintStack();\n\n")
    generated_h.close()


def create_functions_struct(filename):

    add_comma = False
    generated_h = open(os.path.join(TESTSDIR, filename+'.h'), "a")
    generated_h.write("\n\n#define BORDER_ARRAY_SIZE 32\n")
    generated_h.write("#define FUNC_NUM "+ str(len(function_pointer_list)) +"\n")
    generated_h.write("#define PATTERN_SIZE 4\n")
    generated_h.write("#define INIT_VALUE 190\n")
    generated_h.write("#define MAX_CHAR_VALUE 256\n")
    generated_h.write("\ntypedef struct{\n\tint (*fp)();\n\tchar name[64];\n}functionNode;\n")
    generated_h.write("\nstatic char memPattern[PATTERN_SIZE] = {0xDE, 0xAD, 0xFA, 0xCE};\n")
    generated_h.write("\nstatic functionNode funcArray[FUNC_NUM] = {\n")

    for func in function_pointer_list:
        if add_comma:
            generated_h.write(",\n")
        generated_h.write('{'+func+",\""+func[len("StackUsage_"):]+"()\"}")
        add_comma = True

    generated_h.write("};\n\n")
    generated_h.write("#endif //_FUNCTIONS_VECTOR_H_\n")
    generated_h.close()


def create_runner_source(vector_filename):
    runner_c = open(os.path.join(TESTSDIR, 'TestSuiteRunner.c'), "w")

    runner_c.write('/* This file was generated automatically */\n')
    runner_c.write("#include \""+vector_filename+".h\"\n\n")
    runner_c.write("void main()\n{\n")
    runner_c.write("\tint i = 0;\n")
    runner_c.write("\tfor (; i < FUNC_NUM ; ++i)\n\t{\n")
    runner_c.write("\t\tprintf(\"%s function used: %d bytes in the stack\\n\", funcArray[i].name ,funcArray[i].fp());\n\t}\n")
    runner_c.write("\tprintf(\"Test Finished!\\n\");\n")
    runner_c.write("}\n")


def create_runner_header():
    generated_h = open(os.path.join(TESTSDIR, 'TestSuiteRunner.h'), "w")
    generated_h.write('/**********************************************************************\n')
    generated_h.write('* This file was generated automatically and it describes the generated\n')
    generated_h.write('* Source file "TestSuiteRunner.c" which contains the test runner function\n')
    generated_h.write('* for the listed functions in the "TargetFunction.txt" file.\n')
    generated_h.write('* Please do NOT edit these files (header and source) for requests please\n')
    generated_h.write('* send an email to PAL team \n')
    generated_h.write('**********************************************************************/\n\n')
    generated_h.write("#ifndef _TES_SUITE_RUNNER_H_\n")
    generated_h.write("#define _TES_SUITE_RUNNER_H_\n")
    generated_h.write("\nint TestSuiteRunner();\n\n")
    generated_h.write("#endif //_TES_SUITE_RUNNER_H_\n")


def generate_paint_stack():
    runner_c = open(os.path.join(TESTSDIR, 'functionsVector.c'), "a")
    runner_c.write("#pragma GCC diagnostic push\n")
    runner_c.write("#pragma GCC diagnostic ignored \"-Wreturn-local-addr\"\n")
    runner_c.write("/* We can not return the address of the (stackArr) directly, it will be NULL in run-time\n")
    runner_c.write("*  Therefore new pointer (arrayPtr) required to hold the address of the (stackArr)*/\n")
    runner_c.write("char* paintStack()\n{\n")
    runner_c.write("\tchar* arrayPtr = NULL;\n")
    runner_c.write("\tchar stackArr[STACK_UNIT_NUM*STACK_UNIT_SIZE] = {0};\n")
    runner_c.write("\tint i = 0;\n")
    runner_c.write("\tfor(i=0; i < STACK_UNIT_NUM*STACK_UNIT_SIZE; ++i)\n\t{\n")
    runner_c.write("\t\t// Painting the stack with memory pattern (DEADFACE) XORed running index to make the stack more unique\n")
    runner_c.write("\t\tstackArr[i] = memPattern[i%PATTERN_SIZE] ^ (i%MAX_CHAR_VALUE);\n\t}\n")
    runner_c.write("\tarrayPtr = stackArr;\n")
    runner_c.write("\treturn arrayPtr;\n}\n")
    runner_c.write("#pragma GCC diagnostic pop\n\n")


def main():
    generate_new_source_files('functionsVector')
    f = open('TargetFunctions.txt', 'r')
    for line in f:
        if line.strip() == 'List Finished!':
            print "Code generation finished successfully"
            break
        if line[0] == "#" or line[0] == "\n":
            continue
        print "Reading new line: "+ line
        list = line.strip().split('$')
        generate_functions('functionsVector', list[0].strip(' '), list[1].strip(' '), list[2].strip(' '), list[3].strip(' '))
    create_functions_struct('functionsVector')
    create_runner_source('functionsVector')
    generate_paint_stack()
    create_runner_header()
if __name__ == '__main__':
    main()
