int32_t ICC_Async_Device_Init (struct s_reader *reader);
int32_t ICC_Async_CardWrite (struct s_reader *reader, unsigned char *cmd, uint16_t lc, unsigned char *rsp, uint16_t *lr);
int32_t ICC_Async_Activate   (struct s_reader *reader, ATR * atr, uint16_t deprecated);
int32_t ICC_Async_GetStatus (struct s_reader *reader, int32_t * card);
int32_t ICC_Async_Close (struct s_reader *reader);
