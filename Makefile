RULESETS_DIR := rulesets
ALL_DIR      := rules

.PHONY: all clean redo help


all:
	@mkdir -p $(ALL_DIR)
	find $(RULESETS_DIR) -mindepth 2 -type f -exec cat "{}" + > rules/yara_rules.yar

clean:
	find $(ALL_DIR) -maxdepth 1 -type l -delete

redo: clean all

help:
	@echo "make all    - symlink rulesets/*/*.yar into all/"
	@echo "make clean - remove symlinks from all/"
	@echo "make redo      - clean + all"
