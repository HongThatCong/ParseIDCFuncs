// Laisanh: beerware license, free to uses, mods, changes. Don't care :D
// Parse IDCFuncs in ida.dll/ida64.dll (IDA 7.x 64 bit)
// Org code: Unknown (can be redplait)
// Port to IDC 7.x, fixed, extended by HTC - VinCSS (a member of Vingroup)
// 11/08/2020 - ver 0.1

#include <idc.idc>

// Reference: expr.hpp of IDA SDK
#define VT_VOID         0
#define VT_STR          1       //< String (obsolete because it cannot store zero bytes).
                                ///< See #VT_STR2
#define VT_LONG         2       ///< Integer (see idc_value_t::num)
#define VT_FLOAT        3       ///< Floating point (see idc_value_t::e)
#define VT_WILD         4       ///< Function with arbitrary number of arguments.
                                ///< The actual number of arguments will be passed in idc_value_t::num.
                                ///< This value should not be used for ::idc_value_t.
#define VT_OBJ          5       ///< Object (see idc_value_t::obj)
#define VT_FUNC         6       ///< Function (see idc_value_t::funcidx)
#define VT_STR2         7       ///< String (see qstr() and similar functions)
#define VT_PVOID        8       ///< void *
#define VT_INT64        9       ///< i64
#define VT_REF          10      ///< Reference

#define EXTFUN_BASE     0x0001  ///< requires open database.
#define EXTFUN_NORET    0x0002  ///< does not return. the interpreter may
                                ///< clean up its state before calling it.
#define EXTFUN_SAFE     0x0004  ///< thread safe function. may be called
                                ///< from any thread.

static GetExtFunFlags(flags)
{
    auto s = "";

    if (EXTFUN_BASE == (flags & EXTFUN_BASE))
        s = "EXTFUN_BASE";

    if (EXTFUN_NORET == (flags & EXTFUN_NORET))
    {
        if (strlen(s) > 0)
            s = s + " | EXTFUN_NORET";
        else
            s = "EXTFUN_NORET";
    }

    if (EXTFUN_SAFE == (flags & EXTFUN_SAFE))
    {
        if (strlen(s) > 0)
            s = s + " | EXTFUN_SAFE";
        else
            s = "EXTFUN_SAFE";
    }

    return s;
}

static GetIDCFuncFlags(ea)
{
    auto flags = 0;

    if (ea)
        flags = get_wide_dword(ea);

    return GetExtFuncFlags(flags);
}

#define MAP_NAME(x, a, b)   { if ((a) == (x)) { return (b); }}

static GetVT(vt)
{
    MAP_NAME(vt, VT_VOID,  "VT_VOID");
    MAP_NAME(vt, VT_STR,   "VT_STR");
    MAP_NAME(vt, VT_LONG,  "VT_LONG");
    MAP_NAME(vt, VT_FLOAT, "VT_FLOAT");
    MAP_NAME(vt, VT_WILD,  "VT_WILD");
    MAP_NAME(vt, VT_OBJ,   "VT_OBJ");
    MAP_NAME(vt, VT_FUNC,  "VT_FUNC");
    MAP_NAME(vt, VT_STR2,  "VT_STR2");
    MAP_NAME(vt, VT_PVOID, "VT_PVOID");
    MAP_NAME(vt, VT_INT64, "VT_INT64");
    MAP_NAME(vt, VT_REF,   "VT_REF");

    return "VT_UNKNOWN";
}

static GetIDCFuncArgs(ea)
{
    auto args = "";
    auto b, t, ia;

    ia = ea;
    if (ia)
    {
        b = get_wide_byte(ia);
        if (0 == b)
            return "VT_VOID";

        while (1)
        {
            t = GetVT(b);
            args = args + t;

            ia = ia + 1;
            b = get_wide_byte(ia);
            if (0 == b)
                break;
            else
                args = args + ", ";
        }
    }

    return args;
}

static ParseExtIDCFuncAt(ia)
{
    auto strCmt = "";
    auto extfun = object();

    del_items(ia, DELIT_SIMPLE, 40);
    create_struct(ia, -1, "ext_idcfunc_t");

    // ext_idcfunc_t: *namename
    extfun.name = get_strlit_contents(get_qword(ia), -1, get_str_type(get_qword(ia)));
    del_items(get_qword(ia), DELIT_SIMPLE, strlen(extfun.name) + 1);
    create_strlit(get_qword(ia), BADADDR);
    strCmt = "IDC name: " + extfun.name;
    if ("" != get_name(ia))
        set_cmt(ia, "ext_idcfunc_t::" + extfun.name, 0);
    else
        set_name(ia, "@ext_idcfunc_t@" + extfun.name, 0);

    // ext_idcfunc_t: *fptr
    extfun.fptr = get_qword(ia + 8);
    add_func(extfun.fptr, BADADDR);
    set_name(extfun.fptr, "idcfunc_" + extfun.name);

    // ext_idcfunc_t: *args
    del_items(get_qword(ia + 0x10), DELIT_SIMPLE, 4);    // at least DWORD
    create_data(get_qword(ia + 0x10), FF_BYTE, 1, BADADDR);
    extfun.args = GetIDCFuncArgs(get_qword(ia + 0x10));
    strCmt = strCmt + "\nFunc args: " + extfun.args;

    // ext_idcfunc_t: *defvals, ndefvals
    extfun.defvals = "";
    extfun.ndefvals = get_wide_dword(ia + 0x20);
    if (extfun.ndefvals > 0)
    {
        del_items(get_qword(ia + 0x18), DELIT_SIMPLE, 4);    // at least DWORD
        create_data(get_qword(ia + 0x18), FF_BYTE, 1, BADADDR);
        extfun.defvals = GetIDCFuncArgs(get_qword(ia + 0x18));
        strCmt = strCmt + sprintf("\nndefvals = %d: %s", extfun.ndefvals, extfun.defvals);
    }

    // ext_idcfunc_t: flags
    extfun.flags = GetIDCFuncFlags(ia + 0x24);
    if ("" != extfun.flags)
        strCmt = strCmt + "\nFunction flags: " + extfun.flags;

    set_func_cmt(extfun.fptr, strCmt, 0);

    msg("%s: %s(%s)", atoa(extfun.fptr), extfun.name, extfun.args);
    if (extfun.ndefvals > 0)
        msg(", ndefvals = %d, defvals: %s", extfun.ndefvals, extfun.defvals);
    msg("\n");

    return 1;
}

static ExtIDCFuncAtScreenEA(void)
{
    return ParseExtIDCFuncAt(get_screen_ea());
}

static ParseExtIDCFuncTable(ea, count)
{
    auto ia = ea;

    if (ea && count)
    {
        for (ia; ia < ea + count * 8 * 5; ia = ia + 8 * 5)
            ParseExtIDCFuncAt(ia);
        return 1;
    }

    return 0;
}

static ParseIDCFuncsTable()
{
    auto ea = get_name_ea_simple("IDCFuncs");
    if (BADADDR == ea)
    {
        msg("\"IDCFuncs\" label not found. Find and name it, base on \"add_idc_func\" export function.");
        return 0;
    }
    else
    {
        // expr.hpp - idcfuncs_t struct
        auto idcfuncs_t = object();

        // for now, manually parsing the structure
        // is favored over deserializing it(o.retrieve())
        set_cmt(ea, "qnty: Number of functions", 0);
        idcfuncs_t.qnty = get_qword(ea);

        set_name(ea + 8, "p_ExtFuncTable");
        set_cmt(ea + 8, "ext_idcfunc_t *funcs: Function table", 0);
        idcfuncs_t.extfun_t_ptr = get_qword(ea + 8);
        set_name(idcfuncs_t.extfun_t_ptr, "ExtFuncTable");

        set_name(ea + 0x10, "p_IDC_Engine_startup");
        set_cmt(ea + 0x10, "Start IDC engine. Called before executing any IDC code", 0);
        idcfuncs_t.idcengine_startup_ptr = get_qword(ea + 0x10);
        set_name(idcfuncs_t.idcengine_startup_ptr, "IDC_Engine_startup");

        set_name(ea + 0x18, "p_IDC_Engine_shutdown");
        set_cmt(ea + 0x18, "Stop IDC engine. Called when all IDC engines finish.", 0);
        idcfuncs_t.idcengine_shutdown_ptr = get_qword(ea + 0x18);
        set_name(idcfuncs_t.idcengine_shutdown_ptr, "IDC_Engine_shutdown");

        set_name(ea + 0x20, "p_IDC_Engine_init_idc");
        set_cmt(ea + 0x20, "Initialize IDC engine. Called once at the very beginning of work", 0);
        idcfuncs_t.idcengine_init_ptr = get_qword(ea + 0x20);
        set_name(idcfuncs_t.idcengine_init_ptr, "IDC_Engine_init_idc");

        set_name(ea + 0x28, "p_IDC_Engine_term_idc");
        set_cmt(ea + 0x28, "Terminate IDC engine. Called once at the very end of work", 0);
        idcfuncs_t.idcengine_term_ptr = get_qword(ea + 0x28);
        set_name(idcfuncs_t.idcengine_term_ptr, "IDC_Engine_term_idc");

        set_name(ea + 0x30, "p_is_database_open");
        set_cmt(ea + 0x30, "Is the database open ?", 0);
        idcfuncs_t.is_database_open_ptr = get_qword(ea + 0x30);
        set_name(idcfuncs_t.is_database_open_ptr, "is_database_open");

        set_name(ea + 0x38, "p_ea2str");
        set_cmt(ea + 0x38, "Convert an address to a string", 0);
        idcfuncs_t.ea2str_ptr = get_qword(ea + 0x38);
        set_name(idcfuncs_t.ea2str_ptr, "ea2str");

        set_name(ea + 0x40, "p_undeclared_variable_ok");
        set_cmt(ea + 0x40, "Should a variable name be accepted without declaration ?", 0);
        idcfuncs_t.undeclared_variable_ok_ptr = get_qword(ea + 0x40);
        set_name(idcfuncs_t.undeclared_variable_ok_ptr, "undeclared_variable_ok");

        update_extra_cmt(ea + 0x48, E_PREV, "; Indexes into the 'f' array. non-positive values mean that the function does not exist");

        set_name(ea + 0x48, "get_unkvar");
        set_cmt(ea + 0x48, "int, retrieve value of an undeclared variable", 0);
        idcfuncs_t.get_unkvar_ptr = get_wide_dword(ea + 0x48);

        set_name(ea + 0x4C, "set_unkvar");
        set_cmt(ea + 0x4C, "int, store a value to an undeclared variable", 0);
        idcfuncs_t.set_unkvar_ptr = get_wide_dword(ea + 0x4C);

        set_name(ea + 0x50, "exec_resolved_func");
        set_cmt(ea + 0x50, "int, execute resolved function", 0);
        idcfuncs_t.exec_resolved_func_ptr = get_wide_dword(ea + 0x50);

        set_name(ea + 0x54, "calc_sizeof");
        set_cmt(ea + 0x54, "int, calculate sizeof(type)", 0);
        idcfuncs_t.calc_sizeof_ptr = get_wide_dword(ea + 0x54);

        set_name(ea + 0x58, "get_field_ea");
        set_cmt(ea + 0x58, "int, get address of the specified field using the type information from the idb", 0);
        idcfuncs_t.get_field_ea_ptr = get_wide_dword(ea + 0x58);

        msg("%X: ExtIDCFuncTable\n", ea + 8);
        ParseExtIDCFuncTable(idcfuncs_t.extfun_t_ptr, idcfuncs_t.qnty);

        return 1;
    }
}

static add_ext_idcfunc_t_struct()
{
    auto id;

    // expr.hpp - ext_idcfunc_t struct
    id = get_struc_id("ext_idcfunc_t");
    if (-1 != id)
        return 1;

    id = add_struc(-1, "ext_idcfunc_t", 0);
    if (-1 == id)
    {
        msg("Could not create ext_idcfunc_t struct\n");
        return 0;
    }

    add_struc_member(id, "name", 0, FF_0OFF | FF_QWORD, -1, 8);
    set_member_cmt(id, 0, "Name of function", 1);

    add_struc_member(id, "fptr", -1, FF_0OFF | FF_QWORD, -1, 8);
    set_member_cmt(id, 8, "Pointer to the Function", 1);

    add_struc_member(id, "args", -1, FF_0OFF | FF_QWORD, -1, 8);
    set_member_cmt(id, 16, "Type of arguments. Terminated with 0", 1);

    add_struc_member(id, "defvals", -1, FF_0OFF | FF_QWORD, -1, 8);
    set_member_cmt(id, 24, "Default argument values", 1);

    add_struc_member(id, "ndefvals", -1, FF_DATA | FF_DWORD, -1, 4);
    set_member_cmt(id, 32, "Number of default values", 1);

    add_struc_member(id, "flags", -1, FF_DATA | FF_DWORD, -1, 4);
    set_member_cmt(id, 36, "EXTFUN_ Function description flags", 1);

    return 1;
}

static main()
{
    auto dll;

    dll = get_root_filename();
    if (("ida.dll" == dll) || ("ida64.dll" == dll))
    {
        if (0 != add_ext_idcfunc_t_struct())
        {
            ParseIDCFuncsTable();
            return 1;
        }
        else
            return 0;
    }
    else
    {
        msg("This script can only operate on an idb file of IDA 7.x ida.dll/ida64.dll\n");
        return 0;
    }
}
