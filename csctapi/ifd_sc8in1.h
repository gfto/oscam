/*
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef CSCTAPI_IFD_SC8IN1_H_
#define CSCTAPI_IFD_SC8IN1_H_

int32_t Sc8in1_Init(struct s_reader *reader);
int32_t Sc8in1_GetStatus(struct s_reader *reader, int32_t *status);
int32_t Sc8in1_Selectslot(struct s_reader *reader, uint16_t slot);
int32_t Sc8in1_GetActiveHandle(struct s_reader *reader, uint8_t onlyEnabledReaders);
int32_t Sc8in1_Close(struct s_reader *reader);
int32_t Sc8in1_InitLocks(struct s_reader *reader);
int32_t MCR_DisplayText(struct s_reader *reader, char *text, uint16_t text_len, uint16_t ch_time, uint8_t blocking);
int32_t Sc8in1_SetBaudrate(struct s_reader *reader, uint32_t baudrate, struct termios *termio, uint8_t cmdMode);

#endif
