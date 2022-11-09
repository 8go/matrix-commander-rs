[![crates.io - Version](
https://img.shields.io/crates/v/matrix-commander
)](https://crates.io/crates/matrix-commander)
[![crates.io - Downloads](
https://img.shields.io/crates/d/matrix-commander
)](https://crates.io/crates/matrix-commander)

<p>
<img
src="https://raw.githubusercontent.com/8go/matrix-commander-rs/master/logos/matrix-commander-rs.svg"
alt="MC logo" height="150">

# matrix-commander-rs
simple but convenient CLI-based Matrix client app for sending, receiving, and much more

# Help create this Rust program!

This project is currently only a vision. The Python package matrix-commander
exists. See [matrix-commander](https://github.com/8go/matrix-commander/).
The vision is to have a compatible program in Rust. I cannot do it myself,
but I can coordinate and merge your pull requests.
This project depends on you. The project will only advance if you provide
the code. Have a look at the repo
[matrix-commander-rs](https://github.com/8go/matrix-commander-rs/).
Please help! :pray: Please contribute code to make this vision a reality,
and to one day have a fully functional and feature-rich
[matrix-commander](https://crates.io/crates/matrix-commander) crate.
Safe!

:heart: :clap: :pray:

# What works so far

- Login with password
- Login with access token (restore login)
- Encryption
- Emoji verification
- Sending one or multiple text message to one or multiple rooms
- Sending one or multiple text message to one or multiple rooms
- Listening for new and incoming messages on one or multiple rooms
- Getting and printing old messages 
- Listing devices
- Creating, leaving and forgetting rooms
- Getting room info
- Logout and removal of device
- Things like argument parsing, logging, output in JSON format, etc.

# What you can do

- Give a :star: on Github. The more stars on Github, the more people will
  see the project. Do it now, thanks. :clap:
- Talk about it to your friends, post it in chatrooms, Hacker News, etc.
  This will give exposure and help find people willing to provide code,
  contributions, and PRs.
- Write code yourself. :rocket:

# Ideas

- Make it compatible with the Python version of `matrix-commander`, i.e.
  same config file, same CLI, etc. The user should be able to run
  the Python `matrix-commander` in the morning, and the Rust
  `matrix-commander` in the afternoon.
- Use similar modules as used in Python, e.g.
  [argparse](https://crates.io/crates/argparse).
- Use [matrix-rust-sdk](https://crates.io/crates/matrix-sdk).
- Use [ruma](https://crates.io/crates/ruma) if and only if and where needed.
- Make it so as much as possible can be done in a single call.
  Currently the send-and-forget is already working:
  `matrix-commander-rs --login password --user-login @john:some.homeserver.org
  --password secret --device matrix-commander-rs --room-default
  \!someRoomId:some.homeserver.org --message Hello --logout me`.

# Immediate action items
- revise existing code, where is it inefficient?
- improve the quality of the existing code. Make it more Rust-esque
  while keeping it simple.
- re-create the `argparse` interface in Rust, making it as similar as
  possible to the Python `argparse` CLI code
- create Github workflow so that the crate on `crates.io` gets
  generated automatically on `pull request` or `push`.
- implement `login` via SSO
- add features found in the Python version to the Rust version
- ...

# Contributors :clap:
- _Add your name here._
- Who will be the first?

# Usage

```
Usage:
  matrix-commander-rs [OPTIONS]

Welcome to "matrix-commander-rs", a Matrix CLI client. ─── On first run
use --login to log in, to authenticate. On second run we suggest to use
--verify to get verified. Emoji verification is built-in which can be used to
verify devices. Or combine both --login and --verify in the first run. On
further runs "matrix-commander-rs" implements a simple Matrix CLI client that
can send messages or files, listen to messages, operate on rooms, etc.
─── ─── This project is currently only a vision. The Python package
"matrix-commander-rs" exists. The vision is to have a compatible program in
Rust. I cannot do it myself, but I can coordinate and merge your pull requests.
Have a look at the repo "https://github.com/8go/matrix-commander-rs/". Please
help! Please contribute code to make this vision a reality, and to one day have
a functional "matrix-commander-rs" crate. Safe!

Optional arguments:
  -h,--help             Show this help message and exit
  --contribute          Please contribute.
  -v,--version          Print version number.
  -d,--debug            Overwrite the default log level. If not used, then the
                        default log level set with environment variable
                        'RUST_LOG' will be used. If used, log level will be set
                        to 'DEBUG' and debugging information will be printed.
                        '-d' is a shortcut for '--log-level DEBUG'. See also
                        '--log-level'. '-d' takes precedence over
                        '--log-level'. Additionally, have a look also at the
                        option '--verbose'.
  --log-level LOG_LEVEL Set the log level by overwriting the default log level.
                        If not used, then the default log level set with
                        environment variable 'RUST_LOG' will be used. Possible
                        values are 'Trace', 'Debug', 'Info', 'Warn', and
                        'Error'. See also '--debug' and '--verbose'.
  --verbose             Set the verbosity level. If not used, then verbosity
                        will be set to low. If used once, verbosity will be
                        high. If used more than once, verbosity will be very
                        high. Verbosity only affects the debug information. So,
                        if '--debug' is not used then '--verbose' will be
                        ignored.
  --login LOGIN         Login to and authenticate with the Matrix homeserver.
                        This requires exactly one argument, the login method.
                        Currently two choices are offered: 'Password' and
                        'Sso'. Provide one of these methods. If you have chosen
                        'Password', you will authenticate through your account
                        password. You can optionally provide these additional
                        arguments: --homeserver to specify the Matrix
                        homeserver, --user-login to specify the log in user id,
                        --password to specify the password, --device to specify
                        a device name, --room-default to specify a default room
                        for sending/listening. If you have chosen 'Sso', you
                        will authenticate through Single Sign-On. A web-browser
                        will be started and you authenticate on the webpage.
                        You can optionally provide these additional arguments:
                        --homeserver to specify the Matrix homeserver,
                        --user-login to specify the log in user id, --device to
                        specify a device name, --room-default to specify a
                        default room for sending/listening. See all the extra
                        arguments for further explanations. ----- SSO (Single
                        Sign-On) starts a web browser and connects the user to
                        a web page on the server for login. SSO will only work
                        if the server supports it and if there is access to a
                        browser. So, don't use SSO on headless homeservers
                        where there is no browser installed or accessible.
  --verify VERIFY       Perform verification. By default, no verification is
                        performed. Verification is currently only offered via
                        Emojis. Hence, specify '--verify Emoji'. If
                        verification is desired, run this program in the
                        foreground (not as a service) and without a pipe. While
                        verification is optional it is highly recommended, and
                        it is recommended to be done right after (or together
                        with) the --login action. Verification is always
                        interactive, i.e. it required keyboard input.
                        Verification questions will be printed on stdout and
                        the user has to respond via the keyboard to accept or
                        reject verification. Once verification is complete, the
                        program may be run as a service. Verification is best
                        done as follows: Perform a cross-device verification,
                        that means, perform a verification between two devices
                        of the *same* user. For that, open (e.g.) Element in a
                        browser, make sure Element is using the same user
                        account as the matrix-commander-rs user (specified with
                        --user-login at --login). Now in the Element webpage go
                        to the room that is the matrix-commander-rs default
                        room (specified with --room-default at --login). OK, in
                        the web-browser you are now the same user and in the
                        same room as matrix-commander-rs. Now click the round
                        'i' 'Room Info' icon, then click 'People', click the
                        appropriate user (the matrix-commander-rs user), click
                        red 'Not Trusted' text which indicated an untrusted
                        device, then click the square 'Interactively verify by
                        Emoji' button (one of 3 button choices). At this point
                        both web-page and matrix-commander-rs in terminal show
                        a set of emoji icons and names. Compare them visually.
                        Confirm on both sides (Yes, They Match, Got it),
                        finally click OK. You should see a green shield and
                        also see that the matrix-commander-rs device is now
                        green and verified in the webpage. In the terminal you
                        should see a text message indicating success. You
                        should now be verified across all devices and across
                        all users.
  --logout LOGOUT       Logout this or all devices from the Matrix homeserver.
                        This requires exactly one argument. Two choices are
                        offered: 'Me' and 'All'. Provide one of these choices.
                        If you choose 'me', only the one device
                        matrix-commander-rs is currently using will be logged
                        out. If you choose 'all', all devices of the user used
                        by matrix-commander-rs will be logged out. While
                        --logout neither removes the credentials nor the store,
                        the logout action removes the device and makes the
                        access-token stored in the credentials invalid. Hence,
                        after a --logout, one must manually remove creditials
                        and store, and then perform a new --login to use
                        matrix-commander-rs again. You can perfectly use
                        matrix-commander-rs without ever logging out. --logout
                        is a cleanup if you have decided not to use this (or
                        all) device(s) ever again.
  --homeserver HOMESERVER
                        Specify a homeserver for use by certain actions. It is
                        an optional argument. By default --homeserver is
                        ignored and not used. It is used by '--login' action.
                        If not provided for --login the user will be queried
                        via keyboard.
  --user-login USER_LOGIN
                        Optional argument to specify the user for --login. This
                        gives the otion to specify the user id for login. For
                        '--login sso' the --user-login is not needed as user id
                        can be obtained from server via SSO. For '--login
                        password', if not provided it will be queried via
                        keyboard. A full user id like '@john:example.com', a
                        partial user name like '@john', and a short user name
                        like 'john' can be given. --user-login is only used by
                        --login and ignored by all other actions.
  --password PASSWORD   Specify a password for use by certain actions. It is an
                        optional argument. By default --password is ignored and
                        not used. It is used by '--login password' and
                        '--delete-device' actions. If not provided for --login
                        the user will be queried via keyboard.
  --device DEVICE       Specify a device name, for use by certain actions. It
                        is an optional argument. By default --device is ignored
                        and not used. It is used by '--login' action. If not
                        provided for --login the user will be queried via
                        keyboard. If you want the default value specify ''.
                        Multiple devices (with different device id) may have
                        the same device name. In short, the same device name
                        can be assigned to multiple different devices if
                        desired.Don't confuse this option with --devices.
  --room-default ROOM_DEFAULT
                        Optionally specify a room as the default room for
                        future actions. If not specified for --login, it will
                        be queried via the keyboard. --login stores the
                        specified room as default room in your credentials
                        file. This option is only used in combination with
                        --login. A default room is needed. Specify a valid room
                        either with --room-default or provide it via keyboard.
  --devices             Print the list of devices. All device of this account
                        will be printed, one device per line. Don't confuse
                        this option with --device.
  --timeout TIMEOUT     Set the timeout of the calls to the Matrix server. By
                        default they are set to 60 seconds. Specify the timeout
                        in seconds. Use 0 for infinite timeout.
  -m,--message MESSAGE  Send one or more messages. Message data must not be
                        binary data, it must be text. Input piped via stdin can
                        additionally be specified with the special character
                        '-'. Since '-' is also a special character for argument
                        parsing, the '-' for stdin pipe has to be escaped
                        twice. In short, use '\\-' to indicated stdin pipe. If
                        you want to feed a text message into the program via a
                        pipe, via stdin, then specify the special character
                        '\\-'. If your message is literally a single letter '-'
                        then use a triple-escaped '-', i.e. '\\\-'. However,
                        depending on which shell you are using and if you are
                        quoting with double qotes or with single quotes, you
                        may have to add more backslashes to achieve double or
                        triple escape sequences. as message in the argument. If
                        you want to read the message from the keyboard use
                        '\\-' and do not pipe anything into stdin, then a
                        message will be requested and read from the keyboard.
                        Keyboard input is limited to one line. The stdin
                        indicator '-' may appear in any position, i.e. -m
                        'start' '\\-' 'end' will send 3 messages out of which
                        the second one is read from stdin. The stdin indicator
                        '-' may appear only once overall in all arguments.
  --markdown            There are 3 message formats for '--message'. Plain
                        text, MarkDown, and Code. By default, if no command
                        line options are specified, 'plain text' will be used.
                        Use '--markdown' or '--code' to set the format to
                        MarkDown or Code respectively. '--markdown' allows
                        sending of text formatted in MarkDown language.
                        '--code' allows sending of text as a Code block.
  --code                There are 3 message formats for '--message'. Plain
                        text, MarkDown, and Code. By default, if no command
                        line options are specified, 'plain text' will be used.
                        Use '--markdown' or '--code' to set the format to
                        MarkDown or Code respectively. '--markdown' allows
                        sending of text formatted in MarkDown language.
                        '--code' allows sending of text as a Code block.
  -r,--room ROOM        Optionally specify one or multiple rooms by room ids.
                        '--room' is used by by various options like
                        '--message', '--file', and some variants of '--listen'.
                        If no '--room' is provided the default room from the
                        credentials file will be used. If a room is provided in
                        the '--room' argument, then it will be used instead of
                        the one from the credentials file. The user must have
                        access to the specified room in order to send messages
                        to it or listen on the room. Messages cannot be sent to
                        arbitrary rooms. When specifying the room id some
                        shells require the exclamation mark to be escaped with
                        a backslash. Not all listen operations allow setting a
                        room. Read more under the --listen options and similar.
  -f,--file FILE        Send one or multiple files (e.g. PDF, DOC, MP4). First
                        files are sent, then text messages are sent. If you
                        want to feed a file into "matrix-commander-rs" via a
                        pipe, via stdin, then specify the special character '-'
                        as stdin indicator. See description of '--message' to
                        see how the stdin indicator '-' is handled. If you pipe
                        a file into stdin, you can optionally use '--file-name'
                        to attach a label and indirectly a MIME type to the
                        piped data. E.g. if you pipe in a PNG file, you might
                        want to specify additionally '--file-name image.png'.
                        As such the label 'image' will be given to the data and
                        the MIME type 'png' will be attached to it.
  --notice              There are 3 message types for '--message'. Text,
                        Notice, and Emote. By default, if no command line
                        options are specified, 'Text' will be used. Use
                        '--notice' or '--emote' to set the type to Notice or
                        Emote respectively. '--notice' allows sending of text
                        as a notice. '--emote' allows sending of text as an
                        emote.
  --emote               There are 3 message types for '--message'. Text,
                        Notice, and Emote. By default, if no command line
                        options are specified, 'Text' will be used. Use
                        '--notice' or '--emote' to set the type to Notice or
                        Emote respectively. '--notice' allows sending of text
                        as a notice. '--emote' allows sending of text as an
                        emote.
  --room-create ROOM_CREATE
                        Create one or multiple rooms. One or multiple
                        roomaliases can be specified. For each alias specified
                        a room will be created. For each created room one line
                        with room id, alias, name and topic will be printed to
                        stdout. If you are not interested in an alias, provide
                        an empty string like ''. The alias provided must be in
                        canocial local form, i.e. if you want a final full
                        alias like '#SomeRoomAlias:matrix.example.com' you must
                        provide the string 'SomeRoomAlias'. The user must be
                        permitted to create rooms. Combine --room-create with
                        --name and --topic to add names and topics to the
                        room(s) to be created. If the output is in JSON format,
                        then the values that are not set and hence have default
                        values are not shown in the JSON output. E.g. if no
                        topic is given, then there will be no topic field in
                        the JSON output. Room aliases have to be unique.
  --room-leave ROOM_LEAVE
                        Leave this room or these rooms. One or multiple room
                        aliases can be specified. The room (or multiple ones)
                        provided in the arguments will be left. You can run
                        both commands '--room-leave' and '--room-forget' at the
                        same time.
  --room-forget ROOM_FORGET
                        After leaving a room you should (most likely) forget
                        the room. Forgetting a room removes the users\' room
                        history. One or multiple room aliases can be specified.
                        The room (or multiple ones) provided in the arguments
                        will be forgotten. If all users forget a room, the room
                        can eventually be deleted on the server. You must leave
                        a room first, before you can forget it.You can run both
                        commands '--room-leave' and '--room-forget' at the same
                        time.
  --name NAME           Specify one or multiple names. This option is only
                        meaningful in combination with option --room-create.
                        This option --name specifies the names to be used with
                        the command --room-create.
  --topic TOPIC         TOPIC [TOPIC ...] Specify one or multiple topics. This
                        option is only meaningful in combination with option
                        --room-create. This option --topic specifies the topics
                        to be used with the command --room-create.
  --sync SYNC           This option decides on whether the program synchronizes
                        the state with the server before a 'send' action.
                        Currently two choices are offered: 'Full' and 'Off'.
                        Provide one of these choices. The default is 'Full'. If
                        you want to use the default, then there is no need to
                        use this option. If you have chosen 'Full', the full
                        state, all state events will be synchronized between
                        this program and the server before a 'send'. If you
                        have chosen 'Off', synchronization will be skipped
                        entirely before the 'send' which will improve
                        performance.
  --listen LISTEN       The '--listen' option takes one argument. There are
                        several choices: 'never', 'once', 'forever', 'tail',
                        and 'all'. By default, --listen is set to 'never'. So,
                        by default no listening will be done. Set it to
                        'forever' to listen for and print incoming messages to
                        stdout. '--listen forever' will listen to all messages
                        on all rooms forever. To stop listening 'forever', use
                        Control-C on the keyboard or send a signal to the
                        process or service. '--listen once' will get all the
                        messages from all rooms that are currently queued up.
                        So, with 'once' the program will start, print waiting
                        messages (if any) and then stop. The timeout for 'once'
                        is set to 10 seconds. So, be patient, it might take up
                        to that amount of time. 'tail' reads and prints the
                        last N messages from the specified rooms, then quits.
                        The number N can be set with the '--tail' option. With
                        'tail' some messages read might be old, i.e. already
                        read before, some might be new, i.e. never read before.
                        It prints the messages and then the program stops.
                        Messages are sorted, last-first. Look at '--tail' as
                        that option is related to '--listen tail'. The option
                        'all' gets all messages available, old and new. Unlike
                        'once' and 'forever' that listen in ALL rooms, 'tail'
                        and 'all' listen only to the room specified in the
                        credentials file or the --room options.
  --tail TAIL           The '--tail' option reads and prints up to the last N
                        messages from the specified rooms, then quits. It takes
                        one argument, an integer, which we call N here. If
                        there are fewer than N messages in a room, it reads and
                        prints up to N messages. It gets the last N messages in
                        reverse order. It print the newest message first, and
                        the oldest message last. If '--listen-self' is not set
                        it will print less than N messages in many cases
                        because N messages are obtained, but some of them are
                        discarded by default if they are from the user itself.
                        Look at '--listen' as this option is related to
                        '--tail'.
  -y,--listen-self      If set and listening, then program will listen to and
                        print also the messages sent by its own user. By
                        default messages from oneself are not printed.
  --whoami              Print the user id used by matrix-commander-rs (itself).
                        One can get this information also by looking at the
                        credentials file.
  --output OUTPUT       This option decides on how the output is presented.
                        Currently offered choices are: 'text', 'json',
                        'json-max', and 'json-spec'. Provide one of these
                        choices. The default is 'text'. If you want to use the
                        default, then there is no need to use this option. If
                        you have chosen 'text', the output will be formatted
                        with the intention to be consumed by humans, i.e.
                        readable text. If you have chosen 'json', the output
                        will be formatted as JSON. The content of the JSON
                        object matches the data provided by the matrix-nio SDK.
                        In some occassions the output is enhanced by having a
                        few extra data items added for convenience. In most
                        cases the output will be processed by other programs
                        rather than read by humans. Option 'json-max' is
                        practically the same as 'json', but yet another
                        additional field is added. The data item
                        'transport_response' which gives information on how the
                        data was obtained and transported is also being added.
                        For '--listen' a few more fields are added. In most
                        cases the output will be processed by other programs
                        rather than read by humans. Option 'json-spec' only
                        prints information that adheres 1-to-1 to the Matrix
                        Specification. Currently only the events on '--listen'
                        and '--tail' provide data exactly as in the Matrix
                        Specification. If no data is available that corresponds
                        exactly with the Matrix Specification, no data will be
                        printed. In short, currently '--json-spec' only
                        provides outputs for '--listen' and '--tail'.
  --get-room-info GET_ROOM_INFO
                        Get the room information such as room display name,
                        room alias, room creator, etc. for one or multiple
                        specified rooms. The included room 'display name' is
                        also referred to as 'room name' or incorrectly even as
                        room title. If one or more room are given, the room
                        informations of these rooms will be fetched. If no room
                        is specified, the room information for the
                        pre-configured default room configured is fetched. If
                        no room is given, '--' must be used. As response room
                        id, room display name, room canonical alias, room
                        topic, room creator, and room encryption are printed.
                        One line per room will be printed.
  --file-name FILE_NAME Specify one or multiple file names for some actions.
                        This is an optional argument. Use this option in
                        combination with options like '--file -' to specify one
                        or multiple file names. Ignored if used by itself
                        without an appropriate corresponding action.
  --rooms               Print the list of past and current rooms. All rooms
                        that you are currently a member of (joined rooms), that
                        you had been a member of in the past (left rooms), and
                        rooms that you have been invited to (invited rooms)
                        will be printed, one room per line. See also
                        '--invited-rooms', '--joined-rooms', and
                        '--left-rooms'.
  --invited-rooms       Print the list of invited rooms. All rooms that you are
                        currently invited to will be printed, one room per
                        line.
  --joined-rooms        Print the list of joined rooms. All rooms that you are
                        currently a member of will be printed, one room per
                        line.
  --left-rooms          Print the list of left rooms. All rooms that you have
                        left in the past will be printed, one room per line.
```
