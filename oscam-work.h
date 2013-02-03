#ifndef OSCAM_THREAD_H_
#define OSCAM_THREAD_H_

int32_t add_job(struct s_client *cl, int8_t action, void *ptr, int32_t len);
void free_joblist(struct s_client *cl);

#endif
