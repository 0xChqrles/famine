NAME			=	famine
SHEL			=	/bin/bash

LD				=	ld
AC				=	nasm
AFLAGS			=	-f elf64
LFLAGS			=	-m elf_x86_64

SRCS_DIR		=	srcs/
ASM_SRCS		=	$(addprefix $(SRCS_DIR), $(SRCS_LIST))
ASM_SRCS_LIST	=	famine.s

OBJS_DIR		=	objs/
OBJS_LIST		=	$(patsubst %.s, %.o, $(ASM_SRCS_LIST))
OBJS			=	$(addprefix $(OBJS_DIR), $(OBJS_LIST))

.PHONY : all clean fclean re

all : $(NAME)

$(NAME) : $(OBJS)
	@echo "\033[37mLinking...\033[0m"
	@$(LD) $(LFLAGS) $^ -o $@
	@echo "\033[32mBinary \033[1;32m$(NAME)\033[1;0m\033[32m created.\033[0m"

$(OBJS_DIR)%.o : $(SRCS_DIR)%.s
	@mkdir -p $(OBJS_DIR)
	@$(AC) $(AFLAGS) $< -o $@
	@echo "\033[34mCompilation of \033[36m$(notdir $<)\033[34m done.\033[0m"

clean :
	@rm -rf $(OBJS_DIR)
	@echo "\033[31mObjects files \033[1;31m$(OBJS_LIST)\033[1;0m\033[31m removed.\033[0m"

fclean : clean
	@rm -rf $(OBJS_DIR)
	@rm -rf $(NAME)
	@echo "\033[31mBin \033[1;31m$(NAME)\033[1;0m\033[31m removed.\033[0m"

re : fclean all
