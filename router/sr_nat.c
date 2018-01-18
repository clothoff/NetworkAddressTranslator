
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include "sr_if.h"
#include "sr_router.h"
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*Helper function for clearing nat mappings*/
void clear_nat_mapping(struct sr_nat *nat, struct sr_nat_mapping *nat_mapping) {
  printf("REMOVE nat mapping\n");

  struct sr_nat_mapping *prevMapping = nat->mappings;

  if (prevMapping != NULL) {
    if (prevMapping == nat_mapping) {
      nat->mappings = nat_mapping->next;
    } else {
      for (; prevMapping->next != NULL && prevMapping->next != nat_mapping; prevMapping = prevMapping->next) {}
        if (prevMapping == NULL) {return;}
      prevMapping->next = nat_mapping->next;
    }

    if (nat_mapping->type == nat_mapping_icmp) { /* ICMP */
      nat->available_icmp_identifiers[nat_mapping->aux_ext - 1] = 0;
    } else if (nat_mapping->type == nat_mapping_tcp) { /* TCP */
      nat->available_ports[nat_mapping->aux_ext - MIN_PORT] = 0;
    }

    struct sr_nat_connection *curr, *nextConn;
    curr = nat_mapping->conns;

    while (curr != NULL) {
      nextConn = curr->next;
      free(curr);
      curr = nextConn;
    }
    free(nat_mapping);
  }
}


/*Helper function for clearing tcp connection*/
void clear_tcp_conn(struct sr_nat_mapping *mapping, struct sr_nat_connection *conn) {
  printf("[REMOVE] TCP connection\n");
  struct sr_nat_connection *prevConn = mapping->conns;

  if (prevConn != NULL) {
    if (prevConn == conn) {
      mapping->conns = conn->next;
    } else {
      for (; prevConn->next != NULL && prevConn->next != conn; prevConn = prevConn->next) {}
        if (prevConn == NULL) { return; }
      prevConn->next = conn->next;
    }
    free(conn);
  }
}

/*Helper function to check the tcp connection*/
void check_tcp_conns(struct sr_nat *nat, struct sr_nat_mapping *nat_mapping) {
  struct sr_nat_connection *curr, *nextConn;
  time_t curtime = time(NULL);

  curr = nat_mapping->conns;

  while (curr != NULL) {
    nextConn = curr->next;

    if (curr->tcp_state == ESTABLISHED) {
      if (difftime(curtime, curr->last_updated) > nat->tcpEstTimeout) {
        clear_tcp_conn(nat_mapping, curr);
      }
    } else {
      if (difftime(curtime, curr->last_updated) > nat->tcpTransTimeout) {
        clear_tcp_conn(nat_mapping, curr);
      }
    }

    curr = nextConn;
  }
}

void insert_tcp_unsol(struct sr_nat *nat, struct sr_instance *sr, struct sr_if *interface, uint8_t *packet, uint8_t port_src) {
    struct sr_tcp_syn *tcp_syn = (struct sr_tcp_syn *) malloc(sizeof(struct sr_tcp_syn));
    tcp_syn->port_src = port_src;
    tcp_syn->arrived = time(0);
    tcp_syn->interface = interface;
    tcp_syn->sr = sr;
    tcp_syn->packet = packet;
    tcp_syn->next = nat->incoming;
    nat->incoming = tcp_syn;
}
/*
*
*End of helper functions
*
*/


int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */
  nat->incoming = NULL;
  memset(nat->available_ports, 0, sizeof(uint16_t) * TOTAL_PORTS);
  memset(nat->available_icmp_identifiers, 0, sizeof(uint16_t) * TOTAL_ICMP_IDENTIFIERS);

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  struct sr_nat_mapping *curr = nat->mappings;
	while (curr != NULL) {
		struct sr_nat_mapping *prev = curr;
		curr = curr->next;
		free(prev);
	}

	struct sr_tcp_syn *incoming = nat->incoming;
	while (incoming != NULL) {	
		struct sr_tcp_syn *prev = incoming;
		incoming = incoming->next;
		free(prev);
	}

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);
    
    /* Unsolicited incoming SYN timeout */
    struct sr_tcp_syn *incoming = nat->incoming;
    struct sr_tcp_syn *prevIncoming = NULL;
    while (incoming != NULL) {
      if (difftime(curtime, incoming->arrived) >= 6) {
	    /* TODO: Timeout exceeded, send ICMP packet */
	    /*icmp_unreachable(nat->sr, incoming->data, incoming->len, incoming->interface) ??*/
        send_icmp_packet(incoming->sr, 3, 3, incoming->interface, incoming->packet);
	
  /* Remove entry from incoming list*/
	  if (prevIncoming == NULL) {
	    nat->incoming = incoming->next;
	  } else {
	    prevIncoming->next = incoming->next;
	  }  

	  /* Free incoming entry */
	  struct sr_tcp_syn *tmp = incoming;
 	  incoming = incoming->next;
	  free(tmp);			
    
      } else {
	    prevIncoming = incoming;
        incoming = incoming->next;
      }		
    }

    /* handle periodic tasks here */
    struct sr_nat_mapping *curr, *nextMapping;
    curr = nat->mappings;
    /*TODO: SYN packet timeout*/
    
    
    while (curr != NULL) {
      nextMapping = curr->next;
  
      if (curr->type == nat_mapping_icmp) { /* timeout for ICMP */
        if (difftime(curtime, curr->last_updated) > nat->icmpTimeout) {
	  /*ICMP Timeout, remove the entry*/
          clear_nat_mapping(nat, curr);
        }
      } else if (curr->type == nat_mapping_tcp) { /* timeout for TCP */
        check_tcp_conns(nat, curr);
        if (curr->conns == NULL && difftime(curtime, curr->last_updated) > 0.5) {
          clear_nat_mapping(nat, curr);
        }
      }
      curr = nextMapping;
		}      
    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *curr = nat->mappings;
  /*Iterate through mappings*/
  while (curr != NULL) {
  	if (curr->aux_ext == aux_ext && curr->type == type) {
		/* mapping found */
		curr->last_updated = time(NULL);
		copy = malloc(sizeof(struct sr_nat_mapping));
		memcpy(copy, curr, sizeof(struct sr_nat_mapping));
		break;						
	}
	curr = curr->next;
  }
  
  
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *curr = nat->mappings;
   /*Iterate through mappings*/
  while (curr != NULL) {
  	if (curr->aux_int == aux_int && curr->type == type && curr->ip_int == ip_int) {
  		/* mapping found */
  		curr->last_updated = time(NULL);
  		copy = malloc(sizeof(struct sr_nat_mapping));
  		memcpy(copy, curr, sizeof(struct sr_nat_mapping));
  		break;
  	}
  	curr = curr->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thsr_get_interfaceread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = malloc(sizeof(struct sr_nat_mapping));
  assert(mapping != NULL);
  
  mapping->type = type;
  mapping->last_updated = time(NULL);
  mapping->ip_int = ip_int;
  mapping->ip_ext = nat->ip_ext;
  mapping->aux_int = aux_int;
  
  /* Assign a free port number */
  int i; 
  if (type == nat_mapping_tcp) {
    for (i = 0; i < TOTAL_PORTS; i++) {
      if (nat->available_ports[i] == 0) {
        printf("min port is %d\n", mapping->aux_ext);
        mapping->aux_ext = htons(i + MIN_PORT);
        nat->available_ports[i] = 1; 
        break;
      } 
    }
  } else {
    for (i = 0; i < TOTAL_ICMP_IDENTIFIERS; i++) {
      if (nat->available_icmp_identifiers[i] == 0) {
        mapping->aux_ext = htons(i + 1);
        nat->available_icmp_identifiers[i] = 1; 
        break;
      } 
    }
  }

  if (type == nat_mapping_tcp) {
    mapping->conns =(struct sr_nat_connection *) malloc(sizeof(struct sr_nat_connection));
    mapping->conns->next = NULL;  
} else {
    mapping->conns = NULL;
  }
    
  struct sr_nat_mapping *currMapping = nat->mappings;
  nat->mappings = mapping;
  mapping->next = currMapping;
  

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}




