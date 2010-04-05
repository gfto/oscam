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

#include <pthread.h>

int Sc8in1_Init (struct s_reader * reader);
int Sc8in1_GetStatus (struct s_reader * reader, int * status);
int Sc8in1_Card_Changed (struct s_reader * reader);
int Sc8in1_Selectslot(struct s_reader * reader, int slot);

static pthread_mutex_t sc8in1; //semaphore for SC8in1, FIXME should not be global, but one per SC8in1
