#include <stdint.h>
#include <rte_config.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_mbuf_dyn.h>
#include <rte_ip.h>
#include <algorithm>
#include <stdlib.h>
#include <limits.h>
extern "C" {
	#include "lifecycle.h"
	#include "timestamping.h"
	#include "device.h"
}
#include "moonem_common.h"

int burst_size_field_offset = 0; 

uint64_t get_burst_size_dynfield(struct rte_mbuf *m){
	return *RTE_MBUF_DYNFIELD(m, burst_size_field_offset, uint32_t*);
}

void set_burst_size_dynfield(struct rte_mbuf *m, uint64_t burst_size){
	*RTE_MBUF_DYNFIELD(m, burst_size_field_offset, uint32_t*) = burst_size;	
}



extern "C" void init_dynfield_burst_size_offset(){
	burst_size_field_offset = rte_mbuf_dynfield_lookup("dynfield_burst_size", NULL);

	if(burst_size_field_offset<0){
		static const struct rte_mbuf_dynfield dynfield_burst_size_desc = {
			.name = "dynfield_burst_size",
			.size = sizeof(uint32_t),
			.align = __alignof__(uint32_t),
			.flags = 0,
		};
		burst_size_field_offset = rte_mbuf_dynfield_register(&dynfield_burst_size_desc);
	}
}

bool mark_ecn_or_drop(struct rte_mbuf *m) {
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

    // IPv4
    if (ether_type == RTE_ETHER_TYPE_IPV4) {
        struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
        uint8_t ecn = ip_hdr->type_of_service & RTE_IPV4_HDR_ECN_MASK;
		// Check ECN capable
        if (ecn == 0x00) {
            rte_pktmbuf_free(m);
            return false;
        }
        if (ecn != 0x03) {
            ip_hdr->type_of_service |= RTE_IPV4_HDR_ECN_CE;
            // Update checksum (Perhaps change to incremental checksum update for better performance)
            ip_hdr->hdr_checksum = 0;
            ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
        }
    } 
    // IPv6
    else if (ether_type == RTE_ETHER_TYPE_IPV6) {
        struct rte_ipv6_hdr *ip_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
  
        uint32_t vtc_flow = rte_be_to_cpu_32(ip_hdr->vtc_flow);
        uint8_t ecn = (vtc_flow >> 20) & 0x03;
		// Check ECN capable
        if (ecn == 0) { 
            rte_pktmbuf_free(m);
            return false;
        }
        if (ecn != 0x03) { 
            vtc_flow |= (0x03 << 20);
            ip_hdr->vtc_flow = rte_cpu_to_be_32(vtc_flow);
        }
    }
	// Drop if not IP traffic (should not happen)
    else {
        rte_pktmbuf_free(m);
        return false;
    }

    return true;
}

extern "C" void sw_receiver_loop_fwd(int port_id_rx, int queue_id_rx, int port_id_tx, int queue_id_tx, struct moonem_config config){
	struct rte_mbuf* rx_pkts[BURST_SIZE];
	struct rte_mbuf* rx_pkts_loss[BURST_SIZE];
	uint64_t loss_state[2];
	loss_state[0] = config.loss_seed;
	loss_state[1] = 0;
	while (is_running(0)) {
		uint16_t rx = rte_eth_rx_burst(port_id_rx, queue_id_rx, rx_pkts, BURST_SIZE);
		if(rx > 0){
			if(config.loss_type != NONE){
				uint16_t rx_loss = applyLoss(rx, rx_pkts, rx_pkts_loss, loss_state, config);
				dpdk_send_all_packets(port_id_tx, queue_id_tx, rx_pkts_loss, rx_loss);
			}else{
				dpdk_send_all_packets(port_id_tx, queue_id_tx, rx_pkts, rx);
			}
			
		}
	}
}

extern "C" void sw_receiver_loop_delay(int port_id, int queue_id, struct rte_ring* packet_ring, struct moonem_config config){
	uint64_t delay =  rte_get_tsc_hz() * (config.delay / 1000000000.0);

	struct rte_mbuf* bufs[BURST_SIZE];
	struct rte_mbuf* bufs_accept[BURST_SIZE];
	uint64_t loss_state[2];
	loss_state[0] = config.loss_seed;
	loss_state[1] = 0;

	while (is_running(0)) {
		uint16_t rx = rte_eth_rx_burst(port_id, queue_id, bufs, BURST_SIZE);
		if(rx > 0){
			uint64_t timestamp = rte_rdtsc();
			if(config.loss_type != NONE){
				rx = applyLoss(rx, bufs, bufs_accept, loss_state, config);
				for(int i = 0; i < rx; i++){
					set_timestamp_dynfield(bufs_accept[i], timestamp + delay);
					set_burst_size_dynfield(bufs_accept[i], rx-i);
				}
				rte_ring_sp_enqueue_bulk(packet_ring, (void**)bufs_accept, rx, NULL);
			}else{
				for(int i = 0; i < rx; i++){
					set_timestamp_dynfield(bufs[i], timestamp + delay);
					set_burst_size_dynfield(bufs[i], rx-i);
				}
				rte_ring_sp_enqueue_bulk(packet_ring, (void**)bufs, rx, NULL);
			}
		}
	}
}

extern "C" void sw_receiver_loop_rate_token_bucket(int port_id, int queue_id, struct rte_ring* packet_ring, struct moonem_config config){
	uint64_t delay =  rte_get_tsc_hz() * (config.delay / 1000000000.0);
	const double TOKEN_RATE = config.rate / 8.0d / rte_get_tsc_hz() * 1000000.0d;

	struct rte_mbuf* bufs[BURST_SIZE];
	struct rte_mbuf* bufs_accept[BURST_SIZE];
	double previous_timestamp = 0;
	double previous_tokens = 0;
	uint64_t loss_state = config.loss_seed;

	while (is_running(0)) {
		uint16_t rx = rte_eth_rx_burst(port_id, queue_id, bufs, BURST_SIZE);
		if(rx > 0){
			uint64_t recv_timestamp = rte_rdtsc();

			double current_tokens = MIN(previous_tokens + (recv_timestamp - previous_timestamp) * TOKEN_RATE, config.capacity);

			int accept_index = 0;
			for(int i = 0; i < rx; i++){
				uint64_t effective_packet_size = bufs[i]->pkt_len+24;

				if(current_tokens < effective_packet_size){
					rte_pktmbuf_free(bufs[i]);
					continue;
				}

				current_tokens -= effective_packet_size;

				if(config.loss > 0 && wyhash64(&loss_state) < config.loss){
					rte_pktmbuf_free(bufs[i]);
					continue;
				}

				bufs_accept[accept_index++] = bufs[i];
			}
			previous_timestamp = recv_timestamp;
			previous_tokens = current_tokens;

			for(int i = 0; i < accept_index; i++){
				set_timestamp_dynfield(bufs_accept[i], recv_timestamp + delay);
				set_burst_size_dynfield(bufs_accept[i], accept_index-i);
			}

			if(accept_index > 0){
				rte_ring_sp_enqueue_bulk(packet_ring, (void**)bufs_accept, accept_index, NULL);
			}
		}
	}
}

extern "C" void sw_receiver_loop_rate_leaky_bucket(int port_id, int queue_id, struct rte_ring* packet_ring, struct moonem_config config){
	uint64_t delay = rte_get_tsc_hz() * (config.delay / 1000000000.0d);
	const double MAX_TIME_IN_QUEUE_SECONDS = 0.005;
	const double B_P_TSC_TARGET = config.rate * 1000000.0d / rte_get_tsc_hz();
	const double BACKLOG_BOUND = config.capacity / (B_P_TSC_TARGET / 8);
	const double MAX_TIME_IN_QUEUE = rte_get_tsc_hz() * MAX_TIME_IN_QUEUE_SECONDS;

	struct rte_mbuf* bufs[BURST_SIZE];
	struct rte_mbuf* bufs_accept[BURST_SIZE];
	double next_at = 0;
	uint64_t loss_state = config.loss_seed;

	while (is_running(0)) {
		uint16_t rx = rte_eth_rx_burst(port_id, queue_id, bufs, BURST_SIZE);
		if(rx > 0){
			uint64_t recv_timestamp = rte_rdtsc();

			int accept_index = 0;
			for(int i = 0; i < rx; i++){
				uint64_t effective_packet_size = bufs[i]->pkt_len+24;
				uint64_t send_time = recv_timestamp + delay;
				double real_send_time = MAX(send_time, next_at);
				double backlog = real_send_time - send_time;

				if(backlog > BACKLOG_BOUND){
					rte_pktmbuf_free(bufs[i]);
					continue;
				}

				if (backlog > MAX_TIME_IN_QUEUE) {
                    if (!mark_ecn_or_drop(bufs[i])) {
                        continue; 
                    }
                }

				next_at = real_send_time + ((effective_packet_size * 8.0d) / B_P_TSC_TARGET);

				if(config.loss > 0 && wyhash64(&loss_state) < config.loss){
					rte_pktmbuf_free(bufs[i]);
					continue;
				}

				set_timestamp_dynfield(bufs[i], real_send_time);
				set_burst_size_dynfield(bufs[i], 1);
				bufs_accept[accept_index++] = bufs[i];
			}

			if(accept_index > 0){
				rte_ring_sp_enqueue_bulk(packet_ring, (void**)bufs_accept, accept_index, NULL);
			}
		}
	}
}

extern "C" void sw_transmitter_loop_delay(int port_id, int queue_id, struct rte_ring* packet_ring, struct moonem_config config){
	struct rte_mbuf* rx_pkts[BURST_SIZE];
	while (is_running(0)) {
		uint32_t rx = rte_ring_sc_dequeue_burst(packet_ring, (void**)rx_pkts, BURST_SIZE, NULL);
		for (uint32_t i = 0; i < rx; i++) {
			while(get_timestamp_dynfield(rx_pkts[i]) > rte_rdtsc());
			uint32_t packet_burst = MIN(get_burst_size_dynfield(rx_pkts[i]), rx-i);
			dpdk_send_all_packets(port_id, queue_id, &rx_pkts[i], packet_burst);
			i += packet_burst - 1;
		}
	}
}