# ParseIDCFuncs
Parse IDCFuncs (ext_idcfunc_t struct in expr.hpp in IDA SDK) in ida.dll/ida64.dll of IDA 7.x

Create ext_idcfunc_t struct for every IDC function, name and comment prototype of that function.


## Cách sử dụng: 
Làm ơn xem code. Lười viết lắm. Up hình cũng không biết up sao đây, đang mò :(

### Tóm tắt:
IDA v7.2.181105, ida.dll, goto 0x00000000102DC310, name thành IDCFuncs

IDA v7.2.181105, ida64.dll, goto 0x00000000102E4330 -> IDCFuncs

IDA v7.3.190614, ida.dll, goto 0x000000001031E1C0 -> IDCFuncs

IDA v7.3.190614, ida64.dll, goto 0x00000000103281C0 -> IDCFuncs

Rồi, run script, nó sẽ làm hết, in ra msg window

Sau đó goto add_idc_func function, find all xref to funtion này, bạn sẽ thấy các vùng data là struct ext_idcfunc_t truyền vào.

Nếu các vùng data đó chưa được define thành ext_idcfunc_t struct, got đầu vùng data đó, ngay pointer chỉ đến IDC function name.

Switch Python command line mode sang IDC, gõ: ExtIDCFuncAtScreenEA();  rồi Enter.

Sẽ tạo ext_idcfunc_t tại screen EA đó.

Tương tự như vậy cho các vùng data khác truyền vào cho add_idcfunc_t.

Hy vọng các bạn thấy hữu ích :D
