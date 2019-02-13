#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pthread.h>

#include "oamsim.h"


#define NUM_CLI_COMMANDS 10
#define ARG(p) if ((cmd = strtok(p, " ")) == NULL) \
	            goto ERROR_COMMAND;

#define CLI printf

#define CLI_STATUS(a) (a < OK) ? "ERROR" : "OK"

pthread_t cli_thread;
pthread_t py_thread;
pthread_t ccm_tx_thread;

int init_python_msg = FALSE;
int is_cli_running = FALSE;
int is_py_running = FALSE;


//COMEBACK TLV
char *cli_help[NUM_CLI_COMMANDS] =
{"config  mep    mepid    <val>             md name   <val>            level <val>     ma <val> assoc-id <val> interval <milliseconds>",
 "destroy mep    intf     <mep interface>",
 "config  mep    intf     <mep interface>   interval  <milliseconds>",
 "set     tlv    mep-intf <mep interface>   type      <type-val>       size <size-val> val <tlv-val>",
 "del     tlv    mep-intf <mep interface>   type      <type-val>",
 "send    edm    mep-intf <mep interface>   duration  <in seconds>",
 "show    tlv    mep-intf <mep interface>",
 "show    status mep intf <mep interface>",
 "show    all    meps",
 "exit"
};

int parse_cli_cmd_and_create_mep(struct oamsim_cli_msg *oam_msg)
{
    char *cmd;

    /* config mep mepid <val> md ...*/
    ARG(NULL);
    if (strcmp(cmd, "md") == 0) {
	/* config mep mepid <val> md name...*/
	ARG(NULL);
	if (strcmp(cmd, "name") == 0) {
	    /* config mep mepid <val> md name <val>...*/
	    ARG(NULL);
	    strcpy(&oam_msg->md_name, cmd);
	    /* config mep mepid <val> md name <val> level...*/
	    ARG(NULL);
	    if (strcmp(cmd, "level") == 0) {
		/* config mep mepid <val> md name <val> level <val>...*/
		ARG(NULL);
		sscanf(cmd, "%d", &oam_msg->md_level);
		/* config mep mepid <val> md name <val> level <val> ma...*/
		ARG(NULL); 
		if (strcmp(cmd, "ma") == 0) {
		    /* config mep mepid <val> md name <val> level <val> ma <val>...*/
		    ARG(NULL); 
		    strcpy(&oam_msg->ma_name, cmd);
		    /* config mep mepid <val> md name <val> level <val> ma <val> assoc-id...*/
		    ARG(NULL); 
		    if (strcmp(cmd, "assoc-id") == 0) {
			/* config mep mepid <val> md name <val> level <val> ma <val> assoc-id <val>...*/
			ARG(NULL);
		        sscanf(cmd, "%d", &oam_msg->assoc_id);	
			/* config mep mepid <val> md name <val> level <val> ma <val> assoc-id <val> interval...*/
			ARG(NULL); 
			if (strcmp(cmd, "interval") == 0) {
			    /* config mep mepid <val> md name <val> level <val> ma <val> assoc-id <val> interval <val>...*/
			    ARG(NULL); 
			    sscanf(cmd, "%d", &oam_msg->mep_interval);
			    return oam_mep_create(oam_msg);
			}
		    }
		}
	    }
	}
    }

ERROR_COMMAND:
    CLI("Invalid command\n");    
    return -1;
}

int oam_cli_mep_info_display(struct oamsim_cli_msg *msg)
{
    uint   mep_intf = msg->mepIntf;
    struct cfm_tx_mep *mep_list = cfm_info.mep_list;
    struct cfm_mep *mep;

    if (is_mep_intf_valid(mep_intf) == FALSE)
        return -1;

    if (mep_list == NULL)
        return -1;

    mep = get_mep_by_intf(mep_intf);
    if (mep == NULL)
        return -1;

    CLI("MEP INTF: %d  MEPID: %d  MD_NAME: %s  MD_LEVEL: %d  MA_NAME: %s  ASSOC_ID: %d  INTERVAL: %d  TX_COUNT: %u\n",
         mep->tx_mep->mep_if, mep->mep_id, mep->md->md_name, mep->md->md_level, mep->ma->ma_name, mep->assoc_id, mep->cc.tx_interval, mep->cc.tx_count);
 
    return OK;
}


int oam_cli_print_all_meps(void)
{
    struct cfm_md *md;
    struct cfm_ma *ma;
    struct cfm_mep *mep;

    md = cfm_info.md_list;

    CLI("\n\nTotal MEPs configured: %d\n", cfm_info.mep_count);
    CLI("Total MDs configured : %d\n", cfm_info.md_count); 

    while (md != NULL) {
	CLI("\n\n----------------------------------------\n");
        CLI("MD_NAME                : %s\n", md->md_name);
        CLI("MD_LEVEL               : %d\n", md->md_level);
	CLI("Total MAs in this MD   : %d\n", md->ma_count);

	ma = md->ma_list;

	while (ma != NULL) {
	    CLI("\n\n");
	    CLI("MA_NAME               : %s\n", ma->ma_name);
	    CLI("Total MEPs in this MA : %d\n", ma->mep_count);

	    mep = ma->mep_list;

	    while (mep != NULL) {
                CLI("MEP_INTF: %d  MEPID: %d ASSOC_ID: %d INTERVAL: %d TX_COUNT: %u\n", 
		    mep->tx_mep->mep_if, mep->mep_id, mep->assoc_id, mep->cc.tx_interval, mep->cc.tx_count);
		mep = mep->list.nxt;
	    }

	    ma = ma->list.nxt;
	}
        
	md = md->list.nxt;
    }

    return OK;
}

int oam_show_mep_tlv(struct oamsim_cli_msg *msg)
{
    uint mep_intf = msg->mepIntf;
    struct cfm_mep *mep_list = cfm_info.mep_list;
    struct cfm_mep *mep;
    struct cfm_tlv *tlv;

    if (is_mep_intf_valid(mep_intf) == FALSE)
        return -1;

    if (mep_list == NULL)
        return -1;

    mep = get_mep_by_intf(mep_intf);
    if (mep == NULL)
        return -1;

    CLI("\nMEP_INTF: %d MEP_ID: %d\n",msg->mepIntf, mep->mep_id);
    CLI("---------------------------------------------------\n");
    CLI("Following are the TLVs configured for this MEP: \n");
    for (tlv = mep->tlv_list; tlv != NULL; tlv = tlv->list.nxt) {
	if (tlv->tlv_type == 2 || tlv->tlv_type == 4)
            CLI("TLV_TYPE: %d TLV_SIZE: %d TLV_VALUE: %x\n", tlv->tlv_type, tlv->tlv_size, tlv->tlv_val[0]);
	else
	    CLI("TLV_TYPE: %d TLV_SIZE: %d TLV_VALUE: %s\n", tlv->tlv_type, tlv->tlv_size, tlv->tlv_val);
    }    

    return OK;
}

int process_cli_command(uchar *argv)
{
    int i;
    int result = -1;
    char *cmd;
    struct oamsim_cli_msg oam_msg;

	if (strcmp(argv, "\0") == 0)
            return;
	else if (strcmp(argv, "?") == 0) {
	    for (i = 0; i < NUM_CLI_COMMANDS; i++)
		CLI("%s\n", cli_help[i]);

	    return;
	}

        /* Get the first command */	
	ARG(argv);

	/* configure/destroy/set/del/show/send/exit are the valid commands at this level */
	if (strcmp(cmd, "config") == 0) {
	    ARG(NULL);

	    /* Only 'mep' command is valid at this level 
	     *
	     * cmd: configure mep mepid/mep-interface .....
	     *
	     * */
	    if (strcmp(cmd, "mep") == 0) {
	        ARG(NULL);
                
		/* At this level, mepid/mep-interface are the valid commands*/
		if (strcmp(cmd, "mepid") == 0) {
		    ARG(NULL);
		    sscanf(cmd, "%d", &oam_msg.mepid);

		    /* Create mep and print mep-interface number */
		    CLI("MEP interface: %d\n", parse_cli_cmd_and_create_mep(&oam_msg));

		    return;
		} else if (strcmp(cmd, "intf") == 0) {
		    ARG(NULL); /* MEP Interface id */
		    sscanf(cmd, "%d", &oam_msg.mepIntf);

	            /* Valid commands at this level are: interval
		     *
		     * cmd: configure mep mep-interface <val> interval/tlv ...
		     *
		     * */
		    ARG(NULL);
	            if (strcmp(cmd, "interval") == 0) {
		        ARG(NULL);
			sscanf(cmd, "%d", &oam_msg.mep_interval);
		        CLI("%s\n", CLI_STATUS(oam_mep_interval_set(&oam_msg)));
                        return;
	            }  /* end of interval subcommands */ 
	        } /* end of mepid/mep-interface subcommands */ 
	    } /* end of mep config command */
	} else if (strcmp(cmd, "destroy") == 0) {
	    ARG(NULL);

	    if (strcmp(cmd, "mep") == 0) {
		ARG(NULL);

		if (strcmp(cmd, "intf") == 0) {
		    ARG(NULL);

		    sscanf(cmd, "%d", &oam_msg.mepIntf);
		    CLI("%s\n", CLI_STATUS(oam_mep_destroy(&oam_msg)));
		    return;
		}
	    }
	} else if (strcmp(cmd, "set") == 0) { /* set tlv */
	    ARG(NULL);
            if (strcmp(cmd, "tlv") == 0) {
		ARG(NULL);
		if (strcmp(cmd, "mep-intf") == 0) {
		    ARG(NULL);
		    sscanf(cmd, "%d", &oam_msg.mepIntf);
                    
		    ARG(NULL);
		    if (strcmp(cmd, "type") == 0) {
                        ARG(NULL);
                        sscanf(cmd, "%d", &oam_msg.tlv_type);
			
			ARG(NULL);
			if (strcmp(cmd, "size") == 0) {
			    ARG(NULL);
			    sscanf(cmd, "%d", &oam_msg.tlv_size);
                            
			    ARG(NULL);
			    if (strcmp(cmd, "val") == 0) {
				ARG(NULL);
				if ((oam_msg.tlv_type == 2) || (oam_msg.tlv_type == 4)) {
				    int tlv_val;
				    sscanf(cmd, "%d", &tlv_val);
                                    oam_msg.tlv_val[0] = tlv_val & 0xF;
				} else  {/* custom tlv */
				    strcpy(&oam_msg.tlv_val, cmd);
				    if (strlen(&oam_msg.tlv_val) > 40) {
					LOG("TLV value length is to long. Maximum supported TLV length is 40 Bytes\n");
					CLI("%s\n", CLI_STATUS(-1));
				        return;
				    }
				}
				    
				CLI("%s\n", CLI_STATUS(oam_mep_tlv_set(&oam_msg)));
				return;
			    }
			}
		    }
		}
	    }	    

	} else if (strcmp(cmd, "del") == 0) { /* del tlv */
	    ARG(NULL);
	    if (strcmp(cmd, "tlv") == 0) {
		ARG(NULL);
		if (strcmp(cmd, "mep-intf") == 0) {
		    ARG(NULL);
		    sscanf(cmd, "%d", &oam_msg.mepIntf);
                    
		    ARG(NULL);
		    if (strcmp(cmd, "type") == 0) {
			ARG(NULL);
			sscanf(cmd, "%d", &oam_msg.tlv_type);
			CLI("%s\n", CLI_STATUS(oam_mep_tlv_delete(&oam_msg)));
			return;
		    }
		}
	    }
	} else if (strcmp(cmd, "show") == 0) {
	    /* Only 'show status mep', 'show all meps'
	     * and 'show mep tlv' commands are valid at this level
	    */
	    ARG(NULL);
            if (strcmp(cmd, "tlv") == 0) {
		ARG(NULL);
		if (strcmp(cmd, "mep-intf") == 0) {
		     ARG(NULL);
		     sscanf(cmd, "%d", &oam_msg.mepIntf);
		     CLI("%s\n", CLI_STATUS(oam_show_mep_tlv(&oam_msg)));
		     return;
		}
	    } else if (strcmp(cmd, "status") == 0) {
		ARG(NULL);

		if (strcmp(cmd, "mep") == 0) {
		    ARG(NULL);
                   
                    if (strcmp(cmd, "intf") == 0) {
			ARG(NULL);
                        sscanf(cmd, "%d", &oam_msg.mepIntf);
			CLI("%s\n", CLI_STATUS(oam_cli_mep_info_display(&oam_msg)));
			return;
		    }
		}
	    } else if (strcmp(cmd, "all") == 0) {
		ARG(NULL);

		if (strcmp(cmd, "meps") == 0) {
		    CLI("%s\n", CLI_STATUS(oam_cli_print_all_meps()));
		    return;
		}
	    }
	} else if (strcmp(cmd, "send") == 0) {
	    ARG(NULL);
	    if (strcmp(cmd, "edm") == 0) {
		ARG(NULL);
                if (strcmp(cmd, "mep-intf") == 0) {
		    ARG(NULL);
                    sscanf(cmd, "%d", &oam_msg.mepIntf);
		    ARG(NULL);
		    if (strcmp(cmd, "duration") == 0) {
			ARG(NULL);
			sscanf(cmd, "%d", &oam_msg.edm_duration);
			CLI("%s\n", CLI_STATUS(oam_send_edm_pkt(&oam_msg)));
			return;
		    }
		}
	    }
	} else if (strcmp(cmd, "exit") == 0) {
	    oamsim_tx_cleanup();
	    if (init_python_msg)
		is_py_running = FALSE;
            else
	        is_cli_running = FALSE;

	    return;
	}

ERROR_COMMAND: 
        CLI("Invalid command\n");	
}

void cli_thread_handler(void *ptr)
{
    char argv[500];

    while (is_cli_running) {
        CLI("OAMSIM>");
        gets(&argv);
        process_cli_command(&argv);
    }

    pthread_exit(NULL);
}

int oamsim_cli_init()
{
    is_cli_running = TRUE;
    return pthread_create(&cli_thread, NULL, cli_thread_handler, NULL);
}

void py_thread_handler(void *ptr)
{
    int rd_fd = -1;
    int wr_fd = -1;
    char msg[500], argv[500];
    char resp[500];

    char *rd_fifo = "oamsim_msg";
    char *wr_fifo = "oamsim_resp";

    mkfifo(rd_fifo, 0666);
    mkfifo(wr_fifo, 0666);

    while (is_py_running) {
	//memset(&argv, '\0', sizeof(argv));
        memset(&msg, '\0', sizeof(msg));

        /* read cmd from fifo */
        rd_fd = open(rd_fifo, O_RDONLY);
	read(rd_fd, &msg, sizeof(msg));
	close(rd_fd);
	//strncpy(&argv, &msg, strlen(&msg) - 1);
        process_cli_command(&msg);
	
	wr_fd = open(wr_fifo, O_WRONLY);
	write(wr_fd, "OK", strlen("OK") + 1);
	close(wr_fd);
    }

    pthread_exit(NULL); 

}

int oamsim_python_msg_init()
{
    is_py_running = TRUE;
    return pthread_create(&py_thread, NULL, py_thread_handler, NULL);
}

int main(int argc, char *argv[])
{
    int result = -1;
    int sock_fd = -1;
    char *tmp1, *ethIntf;

    if (argc < 2) {
	printf("\n Invalid number of arguments passed");
	//return -1;
    }

        tmp1 = strtok(argv[1], "=");
	if (tmp1 != NULL) {
	    if (strcmp(tmp1, "interface") == 0) {
		ethIntf = strtok(NULL, "");
		if (ethIntf == NULL)
	            return -1;
            } else {
	        printf("\n '%s' is not a valid argument. "
			    "Supported arguments are:", tmp1);
	        printf("\n\t interface=<interface name>");
	    }

	    if (argv[2] != NULL) {
		if (strcmp(argv[2], "py") == 0) {
		    init_python_msg = TRUE;
		} 
	    }
	}

    result = oam_info_init();
    sock_fd = oamsim_network_interface_create(ethIntf);
    result = oamsim_tx_init();
    if (!init_python_msg) {
        result = oamsim_cli_init();
    } else {
        result = oamsim_python_msg_init();
	system("python3 -i oamsim.py");
    }

    if (!init_python_msg)
        pthread_join(cli_thread, NULL);
    else
	pthread_join(py_thread, NULL);

    pthread_join(ccm_tx_thread, NULL);

    return OK;
}
