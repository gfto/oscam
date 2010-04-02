int ICC_Async_Device_Init (struct s_reader *reader);
int ICC_Async_CardWrite (struct s_reader *reader, unsigned char *cmd, unsigned short lc, unsigned char *rsp, unsigned short *lr);
int ICC_Async_Activate   (struct s_reader *reader, ATR * atr, unsigned short deprecated);
int ICC_Async_GetStatus (struct s_reader *reader, int * card);
