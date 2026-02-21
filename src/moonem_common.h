#include <rte_mbuf.h>

#define MAX_LOSS_PARAMETE_COUNT 8

enum loss_type {
	NONE,
	UNIFORM,
	GE,
	NETEM
};

struct moonem_config {
	uint64_t delay;
	uint64_t rate;
	uint64_t capacity;
	uint64_t loss_seed;
	enum loss_type loss_type;
	uint64_t loss;
	uint64_t loss_model_parameters[8];
	uint64_t ce_threshold;
};

#define BURST_SIZE 64
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define MAX(a,b) ((a) > (b) ? (a) : (b))

//https://lemire.me/blog/2019/03/19/the-fastest-conventional-random-number-generator-that-can-pass-big-crush/
static uint64_t wyhash64(uint64_t* state) {
	*state += 0x60bee2bee120fc15;
  	__uint128_t tmp;
  	tmp = (__uint128_t) *state * 0xa3b195354a39b70d;
  	uint64_t m1 = (tmp >> 64) ^ tmp;
  	tmp = (__uint128_t)m1 * 0x1b03738712fad5c9;
  	uint64_t m2 = (tmp >> 64) ^ tmp;
  	return m2;
}

enum ge_var_index { ge_p=0, ge_r=1, ge_h_=2, ge_k_=3, ge_var_num };
static inline bool ge_drop(uint64_t* loss_state, struct moonem_config config) {
	uint64_t* random_state = &loss_state[0];
	uint64_t* state = &loss_state[1];

    uint64_t const x = wyhash64(random_state);
    if ((*state && x < config.loss_model_parameters[ge_p]) || (!*state && x >= config.loss_model_parameters[ge_r])) {
    	*state = false;
        return wyhash64(random_state) < config.loss_model_parameters[ge_h_];
    } else {
        *state = true;
        return wyhash64(random_state) < config.loss_model_parameters[ge_k_];
    }
}

enum netem_model_state { q1=0, q2=1, q3=2, q4=3, q_num };
enum netem_model_state_prob { p_stay=0, p_keep_link_state=1, p_num };
static inline bool netem_drop(uint64_t* loss_state, struct moonem_config config){
	uint64_t* random_state = &loss_state[0];
	uint64_t* state = &loss_state[1];

	bool const drop12_keep34 = *state < q3;
    uint64_t const x = wyhash64(random_state);
    uint64_t const stay = config.loss_model_parameters[(*state * 2) + p_stay];
     
    if (x < stay)		// stay in current state
	 	return !drop12_keep34; // drop packet if in state q3 or q4

	if (x < stay + config.loss_model_parameters[(*state * 2) + p_keep_link_state]) // change state, but stay in same link state
		*state ^= 3; 	// q1 <--> q4, q2 <--> q3
	else			// change state and link state (only relevant for q1, q3)
		*state ^= 2;	// q1 <--> q3

	return drop12_keep34;	// drop packet if old state was 1 or 2
}

static inline int applyLoss(uint16_t rx, struct rte_mbuf** bufs, struct rte_mbuf** bufs_send, uint64_t* loss_state, struct moonem_config config){
	int accept_index = 0;
	switch(config.loss_type){
		case NONE:
			return 0;
		case UNIFORM:
			for (int i = 0; i < rx; i++) {
				if(wyhash64(loss_state) < config.loss){
					rte_pktmbuf_free(bufs[i]);
				}else{
					bufs_send[accept_index++] = bufs[i];
				}
			}
			return accept_index;
		case GE:
			for (int i = 0; i < rx; i++) {
				if(ge_drop(loss_state, config)){
					rte_pktmbuf_free(bufs[i]);
				}else{
					bufs_send[accept_index++] = bufs[i];
				}
			}
			return accept_index;
		case NETEM:
			for (int i = 0; i < rx; i++) {
				if(netem_drop(loss_state, config)){
					rte_pktmbuf_free(bufs[i]);
				}else{
					bufs_send[accept_index++] = bufs[i];
				}
			}
			return accept_index;
		default:
			return 0;
	}

}