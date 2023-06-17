#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <iomanip>
#include <capstone/capstone.h>
#include <vector>
#include <map>
#include <elf.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/mman.h>

using namespace std;

typedef struct breakp{
    bool run_text ;
    unsigned long address;
    unsigned long orig_code;
}breaknode;

long long break_addr = -1; 

int wait_status;
pid_t child = 0;
static csh cshandle = 0;
int code_fd = -1;
vector<breaknode> breakptable;

class instruction1 {
public:
	unsigned char bytes[16];
	int size;
	string opr, opnd;
};
static map<long long, instruction1> instructions;

class anchormap {
public:
    char* anchor_mem;
    unsigned long start;
    unsigned long end;
    unsigned long length;
};

Elf64_Shdr text_sectHdr;
unsigned  long text_base = 0;
struct user_regs_struct anchor_regs;
long long entry_rip;
vector<anchormap> anchordata;

void errquit(const char *msg) {
    close(code_fd);
    breakptable.clear();
    anchordata.clear();
    cs_close(&cshandle);
    if (child) {
        kill(child, SIGTERM);
        child = 0;
    }
	perror(msg);
	exit(-1);
}

void print_instruction(long long addr, instruction1 *in) {
	int i;
	char bytes[128] = "";
	if(in == NULL) {
		fprintf(stderr, "0x%012llx:\t<cannot disassemble>\n", addr);
	} else {
		for(i = 0; i < in->size; i++) {
			snprintf(&bytes[i*3], 4, "%2.2x ", in->bytes[i]);
		} 
		fprintf(stderr, "\t0x%llx: %-32s\t%-10s%s\n", addr,  bytes, in->opr.c_str(), in->opnd.c_str());
	}
} // print_instruction



bool intext( unsigned long rip) {
    // return ( rip >= text_sectHdr.sh_addr ) && (rip < (text_sectHdr.sh_addr + text_sectHdr.sh_size));
    return ( rip >= text_base ) && (rip < (text_base + text_sectHdr.sh_size));

} // intext()

void breakpoint( unsigned long target ) {
    // check

    if(  !intext( target ) ) {
        cout << "** breakpoint : 0x" << hex << target << "is out of the range of the text section." << endl;
        return;
    } // if

    struct user_regs_struct now_regs;
    if ( ptrace(PTRACE_GETREGS, child, NULL, &now_regs) < 0)errquit("PTRACE_GETREGS");    
    unsigned long orig_code = ptrace(PTRACE_PEEKTEXT, child, target, 0);
    if(  now_regs.rip == target ) {
        if( break_addr != -1 ) {
            breakpoint( break_addr );
        } // if
        break_addr = target;
    }
    else {
        if(ptrace(PTRACE_POKETEXT, child, target, (orig_code & 0xffffffffffffff00) | 0xcc) != 0)errquit("ptrace(POKETEXT)");
    }

    // 檢查有沒有被設定過了

    for (int i = 0; i < (int)breakptable.size(); i++)
    {
        if (breakptable[i].address == target) {
            breakptable[i].run_text = false;
            return;
        } // if

    } // for
    cout << "** set a breakpoint at 0x" << hex << target << endl;
    breaknode bnode;
    bnode.run_text = false;
    bnode.address = target;
    bnode.orig_code = orig_code;
    breakptable.push_back( bnode );
}  // breakpoint()

void disasm() {
    int size = 5;
    int count;
	cs_insn *insn;
    int buf_size = 64*size;
    char buf[buf_size] = { 0 };
    // char * code;
    // int code_size;
    // 取得現在的rip位子
    struct user_regs_struct now_regs;
    if ( ptrace(PTRACE_GETREGS, child, NULL, &now_regs) < 0)errquit("PTRACE_GETREGS");
    
    unsigned  long rip =  now_regs.rip;

	// map<long long, instruction1>::iterator mi; // from memory addr to instruction
    int have_in_num = 0;
    int offset = 0;
    // cout << text_sectHdr.sh_addr << endl;
    // text_base = now_regs.rip +  text_sectHdr.sh_addr -elfHdr.e_entry;
    // unsigned long code_offset = rip - text_sectHdr.sh_addr  + text_sectHdr.sh_offset ;
    unsigned long code_offset = rip - text_base + text_sectHdr.sh_offset ;

    int code_size =  pread(code_fd, buf, (size_t)buf_size, (off_t)code_offset);

    // for( int i = 0; i < 5; i++ ) {
    //     if((mi = instructions.find(rip)) != instructions.end()) {
    //         print_instruction(rip, &mi->second);
    //         rip += mi->second.size;
    //         offset += mi->second.size;
    //         have_in_num++;
    //     }
    //     else
    //         break;
    // } // for

	if((count = cs_disasm(cshandle, (uint8_t*) buf+offset, code_size, rip, (size_t)(size ), &insn)) > 0) {
        int i;
		for( i = 0; i < count && intext(rip); i++) {
			instruction1 in;
			in.size = insn[i].size;
			in.opr  = insn[i].mnemonic;
			in.opnd = insn[i].op_str;
			memcpy(in.bytes, insn[i].bytes, insn[i].size);
			instructions[insn[i].address] = in;
            print_instruction(rip, &in);
            rip = rip + in.size;
		} // for

        if ( i != (size - have_in_num ) )
            cout << "** the address is out of the range of the text section." << endl;
		cs_free(insn, count);
	} // if
    else 
        cout << "error" ;

} // disasm()

bool ckterminated() {
    if (WIFEXITED(wait_status)) {
        cout << "** the target program terminated." << endl;
        exit(0);
    } // if
    else if( WIFSTOPPED(wait_status) ) {
        // 可以拉去cont那邊
        int signal =  WSTOPSIG(wait_status);
        if( signal == SIGTRAP ) {
        // 遇見int3停下
            struct user_regs_struct now_regs;

            if ( ptrace(PTRACE_GETREGS, child, NULL, &now_regs) < 0)errquit("PTRACE_GETREGS");
            for (int i = 0; i < (int)breakptable.size(); i++) {
                if (breakptable[i].address == now_regs.rip - 1) {
                    breakptable[i].run_text = true;
                    break_addr = breakptable[i].address;
                    if (ptrace(PTRACE_POKETEXT, child, breakptable[i].address, breakptable[i].orig_code) != 0)errquit("PTRACE_POKETEXT");
                    now_regs.rip--;
                    if (ptrace(PTRACE_SETREGS, child, 0, &now_regs) != 0)errquit("PTRACE_SETREGS");
                    cout << "** hit a breakpoint at 0x" << hex   << breakptable[i].address << endl;
                    return true;
                } // if

            }  // for
        } // if
    } // else if

    return false;
} //  ckterminated()



bool si( bool iscont ) {
    if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) errquit("ptrace@parent");
    if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
    // maybe have bug

    // check trace code terminated or not 
    // and If  is a breakpoint, need to restore the code and then run
    if( WIFSTOPPED(wait_status) ) {
        struct user_regs_struct now_regs;
        if ( ptrace(PTRACE_GETREGS, child, NULL, &now_regs) < 0)errquit("PTRACE_GETREGS");
        for (int i = 0; i < (int)breakptable.size(); i++) {
            if (breakptable[i].address == now_regs.rip ) {
                breakptable[i].run_text = true;
                if( break_addr != -1 ) {
                    breakpoint( break_addr );
                } // if
                break_addr = breakptable[i].address;
                if (ptrace(PTRACE_POKETEXT, child, breakptable[i].address, breakptable[i].orig_code) != 0)errquit("PTRACE_POKETEXT");
                cout << "** hit a breakpoint at 0x" << hex   << breakptable[i].address << endl;
                disasm();
                return true;
            } // if

        }  // for
    } // if
    ckterminated();

    // // print dsiasm
    if( !iscont )
        disasm();
    return false;
} // si()

void cont() {
    if( break_addr != -1 ) {

        if(si(true))
            return;
    } // if
    if(ptrace(PTRACE_CONT, child, 0, 0) < 0) errquit("ptrace@parent");
    if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
    // check trace code terminated or not 
    // and If  is a breakpoint, need to restore the code and then run
    ckterminated();
    // print dsiasm
    disasm();

} // cont()


void code_data_read( anchormap &code_mem ) {
    unsigned long start = code_mem.start;
    unsigned long end = code_mem.end;
    code_mem.length = code_mem.end - code_mem.start;
    void* addr = mmap(NULL, code_mem.length, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    // cout << "hi :" << addr << endl;
    code_mem.anchor_mem = (char *) addr;
    unsigned long i;
    for( i = 0; i + start < end; i += 8) {
		long long peek;
		errno = 0;
		peek = ptrace(PTRACE_PEEKTEXT, child, i + start, NULL);
        // if( peek > 0)
        //     cout << peek << endl;
		if(errno != 0) break;
		memcpy((code_mem.anchor_mem + i ), &peek, 8);
	} // for
    if ( i == 0 ) {
        cout << "mem error" << endl;
    } // if
    // cout << code_mem.anchor_mem  << endl;
} // code_data_read()

void anchor() {
    for( int i = 0; i < (int)anchordata.size(); i++ ) {
        munmap(anchordata[i].anchor_mem,anchordata[i].length);
    } // for
    anchordata.clear();
    if ( ptrace(PTRACE_GETREGS, child, NULL, &anchor_regs) < 0)errquit("PTRACE_GETREGS");
	char fn[128];
    ssize_t read;
    char *line = NULL;
    size_t len = 0;
	FILE *fp;

	snprintf(fn, sizeof(fn), "/proc/%u/maps", child);
	if((fp = fopen(fn, "rt")) == NULL) errquit("fopen");
    unsigned long mem_start, mem_end;
    char permissioen[64];
    while ((read = getline(&line, &len, fp) != -1 ) ) {
        sscanf(line, "%lx-%lx %s", &mem_start, &mem_end, permissioen  );
        cout << line << endl;
        if ( strstr( permissioen, "w" ) ) {
            anchormap code_mem;
            code_mem.start = mem_start;
            code_mem.end = mem_end;
            code_mem.length = mem_start - mem_end;
            code_data_read( code_mem );
            anchordata.push_back( code_mem );

            // cout << "permission : " << permissioen << "  " << hex <<  code_mem.length << endl;
        } // ifZZ

    } // while
    fclose(fp);

} // anchor()

void memrecover( anchormap &code_mem  ) {
    unsigned long i;
    unsigned long start = code_mem.start;
    unsigned long end = code_mem.end;
    for( i = 0; i + start < end; i += 8) {
        long long poke = *((long long*)(code_mem.anchor_mem  + i));
		errno = 0;
        // if( poke > 0)
        //     cout << poke << endl;
        if( ptrace(PTRACE_POKEDATA, child, (void*)(i + start), poke  ) < 0 )errquit("ptrace@POKEDATA");
	} // for
} // memrecover()


// void memmumap() {

//     struct user_regs_struct attack_regs;
//     errno = 0;

//     if ( ptrace(PTRACE_GETREGS, child, NULL, &attack_regs) < 0)errquit("PTRACE_GETREGS");   
//     unsigned long orig_code = ptrace(PTRACE_PEEKTEXT, child, attack_regs.rip, 0);
//     attack_regs.rax = 11;
//     if(ptrace(PTRACE_POKETEXT, child, attack_regs.rip, (orig_code & 0xffffffffffff0000) | 0x050f ) != 0)errquit("time : ptrace(POKETEXT)");

// 	char fn[128];
//     ssize_t read;
//     char *line = NULL;
//     size_t len = 0;
// 	FILE *fp;

// 	snprintf(fn, sizeof(fn), "/proc/%u/maps", child);
// 	if((fp = fopen(fn, "rt")) == NULL) errquit("fopen");
//     unsigned long mem_start, mem_end;
//     char permissioen[64];
//     while ((read = getline(&line, &len, fp) != -1 ) ) {
//         sscanf(line, "%lx-%lx %s", &mem_start, &mem_end, permissioen  );
//         // cout << line << endl;
//         if ( strstr( line, "[heap]" ) ) {
//             bool have_mem = false;
//             for( int i = 0; i < (int)anchordata.size(); i++ ) {
//                 if( anchordata[i].start == mem_start ) {
//                     have_mem = true;
//                     break;
//                 }

//             } // for     

//             if( !have_mem  ) {
//                 cout << line << endl;
//                 attack_regs.rdi = mem_start;
//                 attack_regs.rsi = mem_end - mem_start;
//                 if ( ptrace(PTRACE_SETREGS, child, NULL, &attack_regs) < 0)errquit(" time : PTRACE_SETREGS");
//                 if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) errquit("ptrace@parent");
//                 if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");

//             } // if

//             // cout << "permission : " << permissioen << "  " << hex <<  code_mem.length << endl;
//         } // if

//     } // while
//     fclose(fp);

//     if(ptrace(PTRACE_POKETEXT, child, attack_regs.rip, orig_code ) != 0)errquit("ptrace(POKETEXT)");


// } // memmumap()

void timetravel() {
    // memmumap();

    for( int i = 0; i < (int)anchordata.size(); i++ ) {
        memrecover( anchordata[i] );
    } // for

    if ( ptrace(PTRACE_SETREGS, child, NULL, &anchor_regs) < 0)errquit("PTRACE_SETREGS");
    break_addr = -1;
    for( int i = 0; i < (int)breakptable.size(); i++ ) {
        if ( breakptable[i].address != anchor_regs.rip  )
            breakpoint( breakptable[i].address );
        else if( breakptable[i].address == anchor_regs.rip ) {
            if (ptrace(PTRACE_POKETEXT, child, breakptable[i].address, breakptable[i].orig_code) != 0)errquit("PTRACE_POKETEXT");
            break_addr = breakptable[i].address;
            break_addr = anchor_regs.rip;
        } // else
    } // for

    disasm();
} // timetravel

void get_elftext( string program_name ) {
    FILE *fp;
    if ((fp = fopen(program_name.c_str(), "rb")) == NULL)errquit("fopen");
    Elf64_Ehdr elfHdr;
    Elf64_Shdr sectHdr;
    fread(&elfHdr, sizeof(elfHdr), 1, fp);
    // find section name
    if (elfHdr.e_ident[EI_MAG0] == 0x7f &&
        elfHdr.e_ident[EI_MAG1] == 'E' &&
        elfHdr.e_ident[EI_MAG2] == 'L' &&
        elfHdr.e_ident[EI_MAG3] == 'F'  ) {

        if (elfHdr.e_ident[EI_CLASS] == ELFCLASS64) {
            fseek(fp, elfHdr.e_shoff + elfHdr.e_shstrndx * sizeof(sectHdr), SEEK_SET);
            fread(&sectHdr, sizeof(sectHdr), 1, fp);
            char *SectNames;
            SectNames = (char *)malloc(sectHdr.sh_size);
            fseek(fp, sectHdr.sh_offset, SEEK_SET);
            fread(SectNames, sectHdr.sh_size, 1, fp);
            // read all section headers, find .rela.plt
            for (int idx = 0; idx < elfHdr.e_shnum; idx++) {
                const char *name = "";

                fseek(fp, elfHdr.e_shoff + idx * sizeof(sectHdr), SEEK_SET);
                fread(&sectHdr, sizeof(sectHdr), 1, fp);

                // print section name
                name = SectNames + sectHdr.sh_name;
                if (strcmp(name, ".text") == 0) {
                    text_sectHdr = sectHdr;
                    cout << "** program '" <<  program_name << "' loaded. entry point 0x" << hex << elfHdr.e_entry << endl;
                    text_base = elfHdr.e_entry;
                    struct user_regs_struct now_regs;
                    if ( ptrace(PTRACE_GETREGS, child, NULL, &now_regs) < 0)errquit("PTRACE_GETREGS");
                    cout << "** program rip: 0x" << hex << now_regs.rip << endl;
                    cout << "** text_sectHdr.sh_addr: 0x" << text_sectHdr.sh_addr << endl;
                    text_base = now_regs.rip +  text_sectHdr.sh_addr -elfHdr.e_entry;
                    entry_rip = now_regs.rip;
                    // program_name.c_str()
                    // char fn[128];
	                // snprintf(fn, sizeof(fn), "/proc/%u/exe", child);
                    if( ( code_fd = open( program_name.c_str(), O_RDONLY) )< 0 ) errquit("open");
                    disasm();
                    fclose(fp);
                    return;
                } // if

                // printf("%u %s\n",  idx, name);
            } // for
        } // if
        else {
            cout << "**   Not 64-bits program!" << endl;
            exit(-1);            
        } // else
        
    } // if
    else {
        cout << "**   Not ELF file!" << endl;;
        exit(-1);
    } // else 

} // gettext()

const vector<string> split(const string &str, const char &delimiter) {
    vector<string> result;
    stringstream ss(str);
    string tok;

    while (getline(ss, tok, delimiter)) {
        result.push_back(tok);
    }
    return result;
}

int main(int argc, char *argv[]) {
    string command;
    vector<string> command_list;
	if(argc < 2) {
		fprintf(stderr, "usage: %s program [args ...]\n", argv[0]);
		return -1;
	}

    if((child = fork()) < 0) errquit("fork");
    if(child == 0) {
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace@child");
        execvp(argv[1], argv+1);
        errquit("execvp");
    } // if
    else {

        string target;
        if(waitpid(child, &wait_status, 0) < 0)
            errquit("waitpid");

        ptrace(PTRACE_ATTACH, child, NULL, NULL);
        if(cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK)
			return -1;
        if (ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL) < 0)errquit("PTRACE_SETOPTIONS");
        get_elftext( argv[1] );
        while(1) {
            cout << "(sdb) ";
            // cin >> command;
            getline(cin, command);
            command_list.clear();
            command_list = split(command, ' ');
            if( command_list.size() == 0 )
                continue;
            else if( command_list[0]  == "si" ) {
                // cout << "si" << endl;
                si(false);
            } // if
            else  if( command_list[0] == "cont" ) {
                // cout << "cont" << endl;
                cont();
            } // if
            else  if( command_list[0] == "break" ) {
                if( command_list.size() == 2 )
                    breakpoint( strtoul(command_list[1].c_str(), NULL, 16) );
                else
                    cout << "**need to enter address";
            } // if
            else  if( command_list[0] == "anchor" ) {
                cout << "** dropped an anchor" << endl;
                anchor();
            } // if
            else  if( command_list[0] == "timetravel" ) {
                cout << "** go back to the anchor point" << endl;
                timetravel();
            } // if
            else  if( command_list[0] == "quit" ) {
                close(code_fd);
                breakptable.clear();
                anchordata.clear();
                cs_close(&cshandle);
                if (child) {
                    kill(child, SIGTERM);
                    child = 0;
                }
                exit(0);
            } // if
        } // while

    } // else
    
	return 0;
}
