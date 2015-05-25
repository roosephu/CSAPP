#ifndef MACRO_ISA
#define MACRO_ISA

/* Instruction Set definition for Y86 Architecture */
/* Revisions:
   2009-03-11:
   Changed RNONE to be 0xF
   Changed J_XX and jump_t to C_XX and cond_t; take_branch to cond_holds
   Expanded RRMOVL to include conditional moves
*/

/**************** Registers *************************/

/* REG_NONE is a special one to indicate no register */
typedef enum { REG_EAX, REG_ECX, REG_EDX, REG_EBX,
               REG_ESP, REG_EBP, REG_ESI, REG_EDI, REG_NONE=0xF, REG_ERR } reg_id_t;

/* Find register ID given its name */
reg_id_t find_register(char *name);
/* Return name of register given its ID */
char *reg_name(reg_id_t id);

/**************** Instruction Encoding **************/

/* Different argument types */
typedef enum { R_ARG, M_ARG, I_ARG, NO_ARG } arg_t;

/* Different instruction types */
typedef enum { I_HALT, I_NOP, I_RRMOVL, I_IRMOVL, I_RMMOVL, I_MRMOVL,
               I_ALU, I_JMP, I_CALL, I_RET, I_PUSHL, I_POPL,
               I_IADDL, I_LEAVE, I_POP2, I_RMSWAP } itype_t;

/* Different ALU operations */
typedef enum { A_ADD, A_SUB, A_AND, A_XOR, A_NONE } alu_t;

/* Default function code */
typedef enum { F_NONE } fun_t;

/* Return name of operation given its ID */
char op_name(alu_t op);

/* Different Jump conditions */
typedef enum { C_YES, C_LE, C_L, C_E, C_NE, C_GE, C_G } cond_t;

typedef enum { READ_HIT, READ_MISS, WRITE_HIT, WRITE_MISS } cache_res_t;

/* Pack itype and function into single byte */
#define HPACK(hi,lo) ((((hi)&0xF)<<4)|((lo)&0xF))

/* Unpack byte */
#define HI4(byte) (((byte)>>4)&0xF)
#define LO4(byte) ((byte)&0xF)

/* Get the opcode out of one byte instruction field */
#define GET_ICODE(instr) HI4(instr)

/* Get the ALU/JMP function out of one byte instruction field */
#define GET_FUN(instr) LO4(instr)

/* Return name of instruction given it's byte encoding */
char *iname(int instr);

/**************** Truth Values **************/
typedef enum { FALSE, TRUE } bool_t;

/* Table used to encode information about instructions */
typedef struct {
    char *name;
    unsigned char code; /* Byte code for instruction+op */
    int bytes;
    arg_t arg1;
    int arg1pos;
    int arg1hi;    /* 0/1 for register argument, # bytes for allocation */
    arg_t arg2;
    int arg2pos;
    int arg2hi;    /* 0/1 */
} instr_t, *instr_ptr;

instr_ptr find_instr(char *name);

/* Return invalid instruction for error handling purposes */
instr_ptr bad_instr();

/***********    Implementation of Memory *****************/
typedef unsigned char byte_t;
typedef int word_t;

#define IS_VALID(blk) ((blk)->flag & 1)
#define SET_INVALID(blk) ((blk)->flag ^= (blk)->flag & 1)
#define IS_DIRTY(blk) (((blk)->flag >> 1) & 1)
#define SET_DIRTY(blk) ((blk)->flag |= 2)
#define UNSET_DIRTY(blk) ((blk)->flag ^= (blk)->flag & 2)
#define GET_TAG(blk) (((blk)->flag >> 3) & 0x1FF)
#define ADDR_TAG(pos) (((pos) >> 7) & 0x1FF)
#define ADDR_SET(pos) (((pos) >> 4) & 0x7)
#define ADDR_OFFSET(pos) ((pos) & 0xF)
#define TAG_PACK(valid, dirty, tag) (((tag) << 2) | (dirty) << 1 | (valid))

#define PACK_BROADCAST(type, addr) ((int)(type) << 16 | (addr))
#define BROADCAST_TYPE(broadcast) ((broadcast) >> 16 & 0xFFFF)
#define BROADCAST_ADDR(broadcast) ((broadcast) & 0xFFFF)

#define NUM_SET (1 << 3)
#define NUM_BLK (1 << 2)
#define BLK_SIZE (1 << 4)

typedef struct {
    int flag;
    byte_t contents[BLK_SIZE];
} cache_blk_rec, *cache_blk_t;

typedef struct {
    cache_blk_rec blks[NUM_SET][NUM_BLK];
} cache_rec, *cache_t;

typedef struct {
    byte_t *shared;
    int fd;
    cache_t cache;
} phy_mem_rec, *phy_mem_t;

/* Represent a memory as an array of bytes */
typedef struct {
    int len;
    word_t maxaddr;
    byte_t *contents;
    phy_mem_t aux;
} mem_rec, *mem_t;

void broadcast(mem_t mem, int type, int addr);
void response(mem_t mem);
cache_blk_t load_cache(mem_t mem, cache_t cache, word_t pos);
cache_blk_t find_cache_blk(cache_t cache, word_t pos);
void commit_cache(mem_t mem, cache_blk_t blk, word_t addr);

/* Create a memory with len bytes */
mem_t init_mem(int len, int reg);
void free_mem(mem_t m);

/* Set contents of memory to 0 */
void clear_mem(mem_t m);

/* Make a copy of a memory */
mem_t copy_mem(mem_t oldm);
/* Print the differences between two memories */
bool_t diff_mem(mem_t oldm, mem_t newm, FILE *outfile);

/* How big should the memory be? */
#ifdef BIG_MEM
#define MEM_SIZE (1<<16)
#else
#define MEM_SIZE (1<<13)
#endif
#define SHARED_MEM_POS (MEM_SIZE >> 2)
#define SHARED_MEM_SIZE (MEM_SIZE >> 1)
#define BUS_MEM_SIZE (MEM_SIZE >> 2)
#define BUS_MEM_POS (SHARED_MEM_POS + SHARED_MEM_SIZE)
#define TOTAL_SHM_SIZE (SHARED_MEM_SIZE + BUS_MEM_SIZE)
#define SHARED_FILE "/tmp/y86-shm"

/*** In the following functions, a return value of 1 means success ***/

/* Load memory from .yo file.    Return number of bytes read */
int load_mem(mem_t m, FILE *infile, int report_error);

/* Get byte from memory */
bool_t get_byte_val(mem_t m, word_t pos, byte_t *dest);

/* Get 4 bytes from memory */
bool_t get_word_val(mem_t m, word_t pos, word_t *dest);

/* Set byte in memory */
bool_t set_byte_val(mem_t m, word_t pos, byte_t val);

/* Set 4 bytes in memory */
bool_t set_word_val(mem_t m, word_t pos, word_t val);

/* Print contents of memory */
void dump_memory(FILE *outfile, mem_t m, word_t pos, int cnt);

/********** Implementation of Register File *************/

mem_t init_reg();
void free_reg();

/* Make a copy of a register file */
mem_t copy_reg(mem_t oldr);
/* Print the differences between two register files */
bool_t diff_reg(mem_t oldr, mem_t newr, FILE *outfile);


word_t get_reg_val(mem_t r, reg_id_t id);
void set_reg_val(mem_t r, reg_id_t id, word_t val);
void dump_reg(FILE *outfile, mem_t r);



/* ****************    ALU Function **********************/

/* Compute ALU operation */
word_t compute_alu(alu_t op, word_t arg1, word_t arg2);

typedef unsigned char cc_t;

#define GET_ZF(cc) (((cc) >> 2)&0x1)
#define GET_SF(cc) (((cc) >> 1)&0x1)
#define GET_OF(cc) (((cc) >> 0)&0x1)

#define PACK_CC(z,s,o) (((z)<<2)|((s)<<1)|((o)<<0))

#define DEFAULT_CC PACK_CC(1,0,0)

/* Compute condition code.    */
cc_t compute_cc(alu_t op, word_t arg1, word_t arg2);

/* Generated printed form of condition code */
char *cc_name(cc_t c);

/* **************** Status types *******************/

typedef enum
    {STAT_BUB, STAT_AOK, STAT_HLT, STAT_ADR, STAT_INS, STAT_PIP } stat_t;

/* Describe Status */
char *stat_name(stat_t e);

/* **************** ISA level implementation *********/

typedef struct {
    word_t pc;
    mem_t r;
    mem_t m;
    cc_t cc;
} state_rec, *state_ptr;

state_ptr new_state(int memlen);
void free_state(state_ptr s);

state_ptr copy_state(state_ptr s);
bool_t diff_state(state_ptr olds, state_ptr news, FILE *outfile);

/* Determine if condition satisified */
bool_t cond_holds(cc_t cc, cond_t bcond);

/* Execute single instruction.    Return status. */
stat_t step_state(state_ptr s, FILE *error_file);

/************************ Interface Functions *************/

#ifdef HAS_GUI
void report_line(int line_no, int addr, char *hexcode, char *line);
void signal_register_update(reg_id_t r, int val);

#endif

#endif
