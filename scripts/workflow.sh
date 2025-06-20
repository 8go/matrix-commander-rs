#!/usr/bin/env bash

echo "Welcome!"
echo "The script outlines the rough workflow"
echo
echo "You have written some code? Let's publish it."

# https://askubuntu.com/questions/1705/how-can-i-create-a-select-menu-in-a-shell-script
PS3="Please enter your choice: "
OPT1="rustup self update   # update rustup"
OPT2="rustup update stable # update rust"
OPT3="cargo upgrades       # show which dependencies in Cargo.toml can be updated, requires cargo-upgrades installed"
OPT4="cargo upgrade        # update dependency versions in Cargo.toml, requires cargo-edit installed"
OPT5="cargo update         # update dependencies"
OPTC="Continue"
OPTQ="Quit"
options=("$OPT1" "$OPT2" "$OPT3" "$OPT4"  "$OPT5" "$OPTC" "$OPTQ")
select opt in "${options[@]}"; do
	if [ "${REPLY,,}" == "c" ]; then opt="$OPTC"; fi
	if [ "${REPLY,,}" == "q" ]; then opt="$OPTQ"; fi
	case ${opt} in
	"$OPT1" | "$OPT2" | "$OPT3" | "$OPT4" | "$OPT5")
		OPTE=${opt%%#*} # remove everything after first #
		echo "Performing: $OPTE"
		$OPTE
		continue
		;;
	"$OPTC")
		echo "On to next step."
		break
		;;
	"$OPTQ" | "quit")
		echo "Quitting program."
		exit 0
		;;
	*) echo "invalid option $REPLY" ;;
	esac
done

PS3="Please enter your choice: "
OPT1="git pull # get the latest from Github"
OPTC="Continue"
OPTQ="Quit"
options=("$OPT1" "$OPTC" "$OPTQ")
select opt in "${options[@]}"; do
	if [ "${REPLY,,}" == "c" ]; then opt="$OPTC"; fi
	if [ "${REPLY,,}" == "q" ]; then opt="$OPTQ"; fi
	case ${opt} in
	"$OPT1")
		OPTE=${opt%%#*} # remove everything after first #
		echo "Performing: $OPTE"
		$OPTE
		break
		;;
	"$OPTC")
		echo "On to next step."
		break
		;;
	"$OPTQ" | "quit")
		echo "Quitting program."
		exit 0
		;;
	*) echo "invalid option $REPLY" ;;
	esac
done

PS3="Please enter your choice: "
OPT1="cargo test                     # run this testcase"
OPT2="tests/test-version.sh          # run this testcase"
OPT3="tests/test-send.sh             # run this testcase"
OPT4="tests/test-devices.sh          # run this testcase"
OPT5="tests/test-rooms.sh            # run this testcase"
OPT6="tests/test-get-profile.sh      # run this testcase"
OPT7="tests/test-get-display-name.sh # run this testcase"
OPTC="Continue"
OPTQ="Quit"
options=("$OPT1" "$OPT2" "$OPT3" "$OPT4" "$OPT5" "$OPT6" "$OPT7" "$OPTC" "$OPTQ")
select opt in "${options[@]}"; do
	if [ "${REPLY,,}" == "c" ]; then opt="$OPTC"; fi
	if [ "${REPLY,,}" == "q" ]; then opt="$OPTQ"; fi
	case ${opt} in
	"$OPT1" | "$OPT2" | "$OPT3" | "$OPT4" | "$OPT5" | "$OPT6" | "$OPT7")
		OPTE=${opt%%#*} # remove everything after first #
		echo "Performing: $OPTE"
		$OPTE
		continue
		;;
	"$OPTC")
		echo "On to next step."
		break
		;;
	"$OPTQ")
		echo "Quitting program."
		exit 0
		;;
	*) echo "invalid option $REPLY" ;;
	esac
done

PS3="Please enter your choice: "
OPT1="scripts/update-1-version.sh --mayor # increment MAJOR version number, incompatible"
OPT2="scripts/update-1-version.sh --minor # increment MINOR version number, new feature"
OPT3="scripts/update-1-version.sh --patch # increment PATCH version number, bug fix"
OPT4="cargo clean"
OPT5="cargo build"
OPT6="scripts/create-help-usage.sh        # create help usage file"
OPT7="scripts/create-help-help.sh         # create help help file"
OPT8="scripts/update-2-help-manual.py     # update help manual file, puts it also into README.md"
OPT9="cargo clippy                        # linting"
OPT10="cargo fmt                           # beautifying"
OPTC="Continue"
OPTQ="Quit"
options=("$OPT1" "$OPT2" "$OPT3" "$OPT4" "$OPT5" "$OPT6" "$OPT7" "$OPT8" "$OPT9" "$OPT10" "$OPTC" "$OPTQ")
select opt in "${options[@]}"; do
	if [ "${REPLY,,}" == "c" ]; then opt="$OPTC"; fi
	if [ "${REPLY,,}" == "q" ]; then opt="$OPTQ"; fi
	case ${opt} in
	"$OPT1" | "$OPT2" | "$OPT3" | "$OPT4" | "$OPT5" | "$OPT6" | "$OPT7" | "$OPT8" | "$OPT9" | "$OPT10")
		OPTE=${opt%%#*} # remove everything after first #
		echo "Performing: $OPTE"
		$OPTE
		continue
		;;
	"$OPTC")
		echo "On to next step."
		break
		;;
	"$OPTQ")
		echo "Quitting program."
		exit 0
		;;
	*) echo "invalid option $REPLY" ;;
	esac
done

PS3="Please enter your choice: "
OPT1="git status           # what is the current status"
OPT2="git add  Cargo.lock Cargo.toml README.md VERSION help.manual.txt help.help.txt help.usage.txt src/emoji_verify.rs src/main.rs src/mclient.rs"
OPT3="cargo package --list # show files containing changes"
OPTC="Continue"
OPTQ="Quit"
options=("$OPT1" "$OPT2" "$OPT3" "$OPTC" "$OPTQ")
select opt in "${options[@]}"; do
	if [ "${REPLY,,}" == "c" ]; then opt="$OPTC"; fi
	if [ "${REPLY,,}" == "q" ]; then opt="$OPTQ"; fi
	case ${opt} in
	"$OPT1" | "$OPT2" | "$OPT3")
		OPTE=${opt%%#*} # remove everything after first #
		echo "Performing: $OPTE"
		$OPTE
		continue
		;;
	"$OPTC")
		echo "On to next step."
		break
		;;
	"$OPTQ")
		echo "Quitting program."
		exit 0
		;;
	*) echo "invalid option $REPLY" ;;
	esac
done

PS3="Please enter your choice: "
OPT1="git commit -a # alternative 1 for commit"
OPT2="git commit # alternative 2 for commit"
OPT3="git commit -a -m 'release: v$(cat VERSION)' # alternative 3 for commit; being lazy"
OPTC="Continue"
OPTQ="Quit"
options=("$OPT1" "$OPT2" "$OPT3" "$OPTC" "$OPTQ")
select opt in "${options[@]}"; do
	if [ "${REPLY,,}" == "c" ]; then opt="$OPTC"; fi
	if [ "${REPLY,,}" == "q" ]; then opt="$OPTQ"; fi
	case ${opt} in
	"$OPT1" | "$OPT2" | "$OPT3")
		OPTE=${opt%%#*} # remove everything after first #
		echo "Performing: $OPTE"
		$OPTE
		break
		;;
	"$OPTC")
		echo "On to next step."
		break
		;;
	"$OPTQ")
		echo "Quitting program."
		exit 0
		;;
	*) echo "invalid option $REPLY" ;;
	esac
done

PS3="Please enter your choice: "
OPT1="scripts/update-5-tag.sh # create new annotated tag"
OPTC="Continue"
OPTQ="Quit"
options=("$OPT1" "$OPTC" "$OPTQ")
select opt in "${options[@]}"; do
	if [ "${REPLY,,}" == "c" ]; then opt="$OPTC"; fi
	if [ "${REPLY,,}" == "q" ]; then opt="$OPTQ"; fi
	case ${opt} in
	"$OPT1")
		OPTE=${opt%%#*} # remove everything after first #
		echo "Performing: $OPTE"
		$OPTE
		break
		;;
	"$OPTC")
		echo "On to next step."
		break
		;;
	"$OPTQ")
		echo "Quitting program."
		exit 0
		;;
	*) echo "invalid option $REPLY" ;;
	esac
done

PS3="Please enter your choice: "
echo "A tag push of major version kicks off the Docker actions workflow on Github."
echo "A tag push of major version kicks off the PiPy actions workflow on Github."
echo "Note: a PR does not trigger Github Actions workflows."
echo "Only pushing a tag kicks off the workflow and only if not a minor version."
echo "Instead of 2 separate pushes, one can use *annotated* tags and ----follow-tags."
OPT1="git push --follow-tags # alternative 1; does both push of changes and push of tag"
OPT2="git push # alternative 2a; 1st push, since there is no tag, no trigger on workflows"
OPT3="git push origin v'$(cat VERSION)' # alternative 2b; 2nd push, pushing tag"
OPT4="git push && git push origin v'$(cat VERSION)' # alternative 3; both pushes"
OPTC="Continue"
OPTQ="Quit"
options=("$OPT1" "$OPT2" "$OPT3" "$OPT4" "$OPTC" "$OPTQ")
select opt in "${options[@]}"; do
	if [ "${REPLY,,}" == "c" ]; then opt="$OPTC"; fi
	if [ "${REPLY,,}" == "q" ]; then opt="$OPTQ"; fi
	case ${opt} in
	"$OPT1" | "$OPT2" | "$OPT3" | "$OPT4")
		OPTE=${opt%%#*} # remove everything after first #
		echo "Performing: $OPTE"
		$OPTE
		break
		;;
	"$OPTC")
		echo "On to next step."
		break
		;;
	"$OPTQ")
		echo "Quitting program."
		exit 0
		;;
	*) echo "invalid option $REPLY" ;;
	esac
done

PS3="Please enter your choice: "
echo "Watch Actions workflows on Github, if any."
echo "Now double-check if everything is in order."
OPT1="git tag --list -n --sort=-refname # list tags"
OPT2="git log --pretty=oneline -n 7 # now it shows tag in commit hash"
OPT3="git log -1 --pretty=%B # details of last commit"
OPT4="git tag --list -n20 $(git describe) # details of last tag"
OPT5="git status # list status"
OPTC="Continue"
OPTQ="Quit"
options=("$OPT1" "$OPT2" "$OPT3" "$OPT4" "$OPT5" "$OPTC" "$OPTQ")
select opt in "${options[@]}"; do
	if [ "${REPLY,,}" == "c" ]; then opt="$OPTC"; fi
	if [ "${REPLY,,}" == "q" ]; then opt="$OPTQ"; fi
	case ${opt} in
	"$OPT1" | "$OPT2" | "$OPT3" | "$OPT4" | "$OPT5")
		OPTE=${opt%%#*} # remove everything after first #
		echo "Performing: $OPTE"
		$OPTE
		continue
		;;
	"$OPTC")
		echo "On to next step."
		break
		;;
	"$OPTQ")
		echo "Quitting program."
		exit 0
		;;
	*) echo "invalid option $REPLY" ;;
	esac
done

PS3="Please enter your choice: "
OPT1="cargo login # log into crates.io"
OPT2="cargo clean"
OPT3="cargo publish"
OPTC="Continue"
OPTQ="Quit"
options=("$OPT1" "$OPT2" "$OPT3" "$OPTC" "$OPTQ")
select opt in "${options[@]}"; do
	if [ "${REPLY,,}" == "c" ]; then opt="$OPTC"; fi
	if [ "${REPLY,,}" == "q" ]; then opt="$OPTQ"; fi
	case ${opt} in
	"$OPT1" | "$OPT2" | "$OPT3")
		OPTE=${opt%%#*} # remove everything after first #
		echo "Performing: $OPTE"
		$OPTE
		continue
		;;
	"$OPTC")
		echo "On to next step."
		break
		;;
	"$OPTQ" | "quit")
		echo "Quitting program."
		exit 0
		;;
	*) echo "invalid option $REPLY" ;;
	esac
done

echo "Bye"

exit 0
