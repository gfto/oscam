#include "globals.h"

#ifdef LEDSUPPORT

#include "module-led.h"

#if defined(__arm__)
struct s_arm_led {
	int32_t led;
	int32_t action;
	time_t start_time;
};

static pthread_t arm_led_thread;
static LLIST *arm_led_actions;

static void arm_switch_led_from_thread(int32_t led, int32_t action) {
	if (action < 2) { // only LED_ON and LED_OFF
		char ledfile[256];
		FILE *f;

		#ifdef DOCKSTAR
			switch(led) {
			case LED1A:snprintf(ledfile, 255, "/sys/class/leds/dockstar:orange:misc/brightness"); break;
			case LED1B:snprintf(ledfile, 255, "/sys/class/leds/dockstar:green:health/brightness"); break;
			case LED2:snprintf(ledfile, 255, "/sys/class/leds/dockstar:green:health/brightness"); break;
			case LED3:snprintf(ledfile, 255, "/sys/class/leds/dockstar:orange:misc/brightness"); break;
			}
		#elif WRT350NV2
			switch(led){
			case LED1A:snprintf(ledfile, 255, "/sys/class/leds/wrt350nv2:orange:power/brightness"); break;
			case LED1B:snprintf(ledfile, 255, "/sys/class/leds/wrt350nv2:green:power/brightness"); break;
			case LED2:snprintf(ledfile, 255, "/sys/class/leds/wrt350nv2:green:wireless/brightness"); break;
			case LED3:snprintf(ledfile, 255, "/sys/class/leds/wrt350nv2:green:security/brightness"); break;
			}
		#else
			switch(led){
			case LED1A:snprintf(ledfile, 255, "/sys/class/leds/nslu2:red:status/brightness"); break;
			case LED1B:snprintf(ledfile, 255, "/sys/class/leds/nslu2:green:ready/brightness"); break;
			case LED2:snprintf(ledfile, 255, "/sys/class/leds/nslu2:green:disk-1/brightness"); break;
			case LED3:snprintf(ledfile, 255, "/sys/class/leds/nslu2:green:disk-2/brightness"); break;
			}
		#endif

		if (!(f=fopen(ledfile, "w"))){
			// FIXME: sometimes cs_log was not available when calling arm_led -> signal 11
			// cs_log("Cannot open file \"%s\" (errno=%d %s)", ledfile, errno, strerror(errno));
			return;
		}
		fprintf(f,"%d", action);
		fclose(f);
	} else { // LED Macros
		switch(action){
		case LED_DEFAULT:
			arm_switch_led_from_thread(LED1A, LED_OFF);
			arm_switch_led_from_thread(LED1B, LED_OFF);
			arm_switch_led_from_thread(LED2, LED_ON);
			arm_switch_led_from_thread(LED3, LED_OFF);
			break;
		case LED_BLINK_OFF:
			arm_switch_led_from_thread(led, LED_OFF);
			cs_sleepms(100);
			arm_switch_led_from_thread(led, LED_ON);
			break;
		case LED_BLINK_ON:
			arm_switch_led_from_thread(led, LED_ON);
			cs_sleepms(300);
			arm_switch_led_from_thread(led, LED_OFF);
			break;
		}
	}
}

static void *arm_led_thread_main(void *UNUSED(thread_data)) {
	uint8_t running = 1;
	while (running) {
		LL_ITER iter = ll_iter_create(arm_led_actions);
		struct s_arm_led *arm_led;
		while ((arm_led = ll_iter_next(&iter))) {
			int32_t led, action;
			time_t now, start;
			led = arm_led->led;
			action = arm_led->action;
			now = time((time_t)0);
			start = arm_led->start_time;
			ll_iter_remove_data(&iter);
			if (action == LED_STOP_THREAD) {
				running = 0;
				break;
			}
			if (now - start < ARM_LED_TIMEOUT) {
				arm_switch_led_from_thread(led, action);
			}
		}
		if (running) {
			sleep(60);
		}
	}
	ll_clear_data(arm_led_actions);
	pthread_exit(NULL);
	return NULL;
}

static void arm_led_start_thread(void) {
	if (cfg.enableled != 1)
		return;
	// call this after signal handling is done
	if (!arm_led_actions) {
		arm_led_actions = ll_create("arm_led_actions");
	}
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	cs_log("starting thread arm_led_thread");
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
	int32_t ret = pthread_create(&arm_led_thread, &attr, arm_led_thread_main, NULL);
	if (ret) {
		cs_log("ERROR: can't create arm_led_thread thread (errno=%d %s)", ret, strerror(ret));
	} else {
		cs_log("arm_led_thread thread started");
		pthread_detach(arm_led_thread);
	}
	pthread_attr_destroy(&attr);
}

static void arm_led(int32_t led, int32_t action) {
	struct s_arm_led *arm_led;
	if (cfg.enableled != 1)
		return;
	if (!arm_led_actions) {
		arm_led_actions = ll_create("arm_led_actions");
	}
	if (cs_malloc(&arm_led,sizeof(struct s_arm_led), -1)) {
		arm_led->start_time = time((time_t)0);
		arm_led->led = led;
		arm_led->action = action;
		ll_append(arm_led_actions, (void *)arm_led);
	}
	if (arm_led_thread) {
		// arm_led_thread_main is not started at oscam startup
		// when first arm_led calls happen
		pthread_kill(arm_led_thread, OSCAM_SIGNAL_WAKEUP);
	}
}

static void arm_led_stop_thread(void) {
	if (cfg.enableled != 1)
		return;
	arm_led(0, LED_STOP_THREAD);
}
#else
static inline void arm_led_start_thread(void) { }
static inline void arm_led_stop_thread(void) { }
static inline void arm_led(int32_t UNUSED(led), int32_t UNUSED(action)) { }
#endif


#ifdef QBOXHD
static void qboxhd_led_blink(int32_t color, int32_t duration) {
	int32_t f;
	if (cfg.enableled != 2)
		return;
	// try QboxHD-MINI first
	if ((f = open(QBOXHDMINI_LED_DEVICE, O_RDWR|O_NONBLOCK)) > -1) {
		qboxhdmini_led_color_struct qbminiled;
		uint32_t qboxhdmini_color = 0x000000;
		if (color != QBOXHD_LED_COLOR_OFF) {
			switch(color) {
				case QBOXHD_LED_COLOR_RED:
					qboxhdmini_color = QBOXHDMINI_LED_COLOR_RED;
					break;
				case QBOXHD_LED_COLOR_GREEN:
					qboxhdmini_color = QBOXHDMINI_LED_COLOR_GREEN;
					break;
				case QBOXHD_LED_COLOR_BLUE:
					qboxhdmini_color = QBOXHDMINI_LED_COLOR_BLUE;
					break;
				case QBOXHD_LED_COLOR_YELLOW:
					qboxhdmini_color = QBOXHDMINI_LED_COLOR_YELLOW;
					break;
				case QBOXHD_LED_COLOR_MAGENTA:
					qboxhdmini_color = QBOXHDMINI_LED_COLOR_MAGENTA;
					break;
			}
			// set LED on with color
			qbminiled.red = (uchar)((qboxhdmini_color&0xFF0000)>>16);  // R
			qbminiled.green = (uchar)((qboxhdmini_color&0x00FF00)>>8); // G
			qbminiled.blue = (uchar)(qboxhdmini_color&0x0000FF);	   // B
			ioctl(f,QBOXHDMINI_IOSET_RGB,&qbminiled);
			cs_sleepms(duration);
		}
		// set LED off
		qbminiled.red = 0;
		qbminiled.green = 0;
		qbminiled.blue = 0;
		ioctl(f,QBOXHDMINI_IOSET_RGB,&qbminiled);
		close(f);
	} else if ((f = open(QBOXHD_LED_DEVICE, O_RDWR |O_NONBLOCK)) > -1) {
		qboxhd_led_color_struct qbled;
		if (color != QBOXHD_LED_COLOR_OFF) {
			// set LED on with color
			qbled.H = color;
			qbled.S = 99;
			qbled.V = 99;
			ioctl(f,QBOXHD_SET_LED_ALL_PANEL_COLOR, &qbled);
			cs_sleepms(duration);
		}
		// set LED off
		qbled.H = 0;
		qbled.S = 0;
		qbled.V = 0;
		ioctl(f,QBOXHD_SET_LED_ALL_PANEL_COLOR, &qbled);
		close(f);
	}
}
#else
static inline void qboxhd_led_blink(int32_t UNUSED(color), int32_t UNUSED(duration)) { }
#endif

void led_status_stopping(void) {
	if (cfg.enableled == 1) {
		arm_led(LED1B, LED_OFF);
		arm_led(LED2,  LED_OFF);
		arm_led(LED3,  LED_OFF);
		arm_led(LED1A, LED_ON);
	}
	if (cfg.enableled == 2) {
		qboxhd_led_blink(QBOXHD_LED_COLOR_YELLOW,  QBOXHD_LED_BLINK_FAST);
		qboxhd_led_blink(QBOXHD_LED_COLOR_RED,     QBOXHD_LED_BLINK_FAST);
		qboxhd_led_blink(QBOXHD_LED_COLOR_GREEN,   QBOXHD_LED_BLINK_FAST);
		qboxhd_led_blink(QBOXHD_LED_COLOR_BLUE,    QBOXHD_LED_BLINK_FAST);
		qboxhd_led_blink(QBOXHD_LED_COLOR_MAGENTA, QBOXHD_LED_BLINK_FAST);
	}
}

void led_status_cw_not_found(ECM_REQUEST *er) {
	if (!er->rc)
		arm_led(LED2, LED_BLINK_OFF);
	if (er->rc < E_NOTFOUND) {
		qboxhd_led_blink(QBOXHD_LED_COLOR_GREEN, QBOXHD_LED_BLINK_MEDIUM);
	} else if (er->rc <= E_STOPPED) {
		qboxhd_led_blink(QBOXHD_LED_COLOR_RED, QBOXHD_LED_BLINK_MEDIUM);
	}
}

void led_status_default(void) {
	arm_led(LED1A, LED_DEFAULT);
	arm_led(LED1A, LED_ON);
}

void led_status_starting(void) {
	arm_led(LED1A, LED_OFF);
	arm_led(LED1B, LED_ON);
	qboxhd_led_blink(QBOXHD_LED_COLOR_YELLOW,  QBOXHD_LED_BLINK_FAST);
	qboxhd_led_blink(QBOXHD_LED_COLOR_RED,     QBOXHD_LED_BLINK_FAST);
	qboxhd_led_blink(QBOXHD_LED_COLOR_GREEN,   QBOXHD_LED_BLINK_FAST);
	qboxhd_led_blink(QBOXHD_LED_COLOR_BLUE,    QBOXHD_LED_BLINK_FAST);
	qboxhd_led_blink(QBOXHD_LED_COLOR_MAGENTA, QBOXHD_LED_BLINK_FAST);
}

void led_status_card_activation_error(void) {
	qboxhd_led_blink(QBOXHD_LED_COLOR_MAGENTA, QBOXHD_LED_BLINK_MEDIUM);
}

void led_status_found_cardsystem(void) {
	qboxhd_led_blink(QBOXHD_LED_COLOR_YELLOW, QBOXHD_LED_BLINK_MEDIUM);
	qboxhd_led_blink(QBOXHD_LED_COLOR_GREEN,  QBOXHD_LED_BLINK_MEDIUM);
	qboxhd_led_blink(QBOXHD_LED_COLOR_YELLOW, QBOXHD_LED_BLINK_MEDIUM);
	qboxhd_led_blink(QBOXHD_LED_COLOR_GREEN,  QBOXHD_LED_BLINK_MEDIUM);
}

void led_status_unsupported_card_system(void) {
	qboxhd_led_blink(QBOXHD_LED_COLOR_MAGENTA, QBOXHD_LED_BLINK_MEDIUM);
}

void led_status_card_detected(void) {
	qboxhd_led_blink(QBOXHD_LED_COLOR_YELLOW, QBOXHD_LED_BLINK_SLOW);
}

void led_status_card_ejected(void) {
	qboxhd_led_blink(QBOXHD_LED_COLOR_RED, QBOXHD_LED_BLINK_SLOW);
}

void led_status_emm_ok(void) {
	arm_led(LED3, LED_BLINK_ON);
	qboxhd_led_blink(QBOXHD_LED_COLOR_BLUE,QBOXHD_LED_BLINK_MEDIUM);
}

void led_init(void) {
	arm_led_start_thread();
}

void led_stop(void) {
	arm_led_stop_thread();
}

#endif
