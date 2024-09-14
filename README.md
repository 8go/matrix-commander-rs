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

# Incompatibilities

Be forewarned.
Version 0.4 is incompatible with previous versions.
The default location of the store has changed.
The directory name of the default store used to be `sledstore`.
Now it is just `store`. The program attempts to rename
the store's directory name automatically. E.g. on Linux it tries
to automatically rename
`~/.local/share/matrix-commander-rs/sledstore/` to
`~/.local/share/matrix-commander-rs/store/`.
If you have used the default store name in the past,
and automatical renaming is failing for you, then rename the store's
directory name from
`sledstore` to `store` manually. Also, some JSON and
text output is different than in previous version. If you are parsing
the output you should do careful testing to adapt to the changed
output.

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
- Manual and Emoji verification
- Sending one or multiple text message to one or multiple rooms
- Sending one or multiple text message to one or multiple rooms
- Listening for new and incoming messages on one or multiple rooms
- Getting and printing old messages
- Listing devices
- Creating, leaving and forgetting rooms
- Kicking, banning, etc. on rooms
- Getting, setting and removing user avatar
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
  `matrix-commander-rs` in the afternoon.
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
- implement `login` via SSO
- add --proxy (see Python documentation)
- add --nossl (see Python documentation)
- add --event (see Python documentation and JSON config file in Pythom repo)
- add --download-media (see Python documentation)
- add other features found in the Python version to the Rust version
- ...

# Contributors :clap:
- _Add your name here._
- Who will be the first?

# Usage

```
Welcome to "matrix-commander-rs", a Matrix CLI client. ─── On the first run use
--login to log in, to authenticate. On the second run we suggest to use
--verify to get verified. Manual verification is built-in and can be used to
verify devices and users. Or combine both --login and --verify in the first
run. On further runs "matrix-commander-rs" implements a simple Matrix CLI
client that can send messages or files, listen to messages, operate on rooms,
etc.  ───  ─── This project is currently only a vision. The Python package
"matrix-commander" exists. The vision is to have a compatible program in Rust.
I cannot do it myself, but I can coordinate and merge your pull requests. Have
a look at the repo "https://github.com/8go/matrix-commander-rs/". Please help!
Please contribute code to make this vision a reality, and to one day have a
feature-rich "matrix-commander-rs" crate. Safe!

Usage: matrix-commander-rs [OPTIONS]

Options:
      --contribute
          Please contribute

  -v, --version [<CHECK>]
          Print version number or check if a newer version exists on crates.io.
          Details:: If used without an argument such as '--version' it will
          print the version number. If 'check' is added ('--version check')
          then the program connects to https://crates.io and gets the version
          number of latest stable release. There is no "calling home" on every
          run, only a "check crates.io" upon request. Your privacy is
          protected. New release is neither downloaded, nor installed. It just
          informs you

          Possible values:
          - check: Check if there is a newer version available

      --usage
          Prints a very short help summary. Details:: See also --help, --manual
          and --readme

  -h, --help
          Prints short help displaying about one line per argument. Details::
          See also --usage, --manual and --readme

      --manual
          Prints long help. Details:: This is like a man page. See also
          --usage, --help and --readme

      --readme
          Prints README.md file, the documenation in Markdown. Details:: The
          README.md file will be downloaded from Github. It is a Markdown file
          and it is best viewed with a Markdown viewer. See also --usage,
          --help and --manual

  -d, --debug...
          Overwrite the default log level. Details:: If not used, then the
          default log level set with environment variable 'RUST_LOG' will be
          used. If used, log level will be set to 'DEBUG' and debugging
          information will be printed. '-d' is a shortcut for '--log-level
          DEBUG'. See also '--log-level'. '-d' takes precedence over
          '--log-level'. Additionally, have a look also at the option
          '--verbose'

      --log-level <LOG_LEVEL>
          Set the log level by overwriting the default log level. Details:: If
          not used, then the default log level set with environment variable
          'RUST_LOG' will be used. See also '--debug' and '--verbose'. An
          example use of RUST_LOG is to use neither --log-level nor --debug,
          and to set RUST_LOG="error,matrix_commander_rs=debug" which turns off
          debugging on all lower level modules and turns debugging on only for
          matrix-commander-rs
          
          [default: none]

          Possible values:
          - none:  None: not set, default
          - error: Error: Indicates to print only errors
          - warn:  Warn: Indicates to print warnings and errors
          - info:  Info: Indicates to to print info, warn and errors
          - debug: Debug: Indicates to to print debug and the rest
          - trace: Trace: Indicates to to print everything

      --verbose...
          Set the verbosity level. Details:: If not used, then verbosity will
          be set to low. If used once, verbosity will be high. If used more
          than once, verbosity will be very high. Verbosity only affects the
          debug information. So, if '--debug' is not used then '--verbose' will
          be ignored

      --plain
          Disable encryption for a specific action. Details:: By default
          encryption is turned on wherever possible. E.g. rooms created will be
          created by default with encryption enabled. To turn encryption off
          for a specific action use --plain. Currently --plain is supported by
          --room-create and --room-dm-create. See also --room-enable-encryption
          which sort of does the opossite for rooms

  -c, --credentials <PATH_TO_FILE>
          Specify path to a file containing credentials. Details:: At login
          (--login), information about homeserver, user, room id, etc. will be
          written to a credentials file. By default, this file is
          "credentials.json". On further runs the credentials file is read to
          permit logging into the correct Matrix account and sending messages
          to the preconfigured room. If this option is provided, the provided
          path to a file will be used as credentials file instead of the
          default one. E.g. ~/.local/share/matrix-commander-rs/credentials.json
          
          [default:
          /home/user/.local/share/matrix-commander-rs/credentials.json]

  -s, --store <PATH_TO_DIRECTORY>
          Specify a path to a directory to be used as "store" for encrypted
          messaging. Details:: Since encryption is always enabled, a store is
          always needed. If this option is provided, the provided directory
          name will be used as persistent storage directory instead of the
          default one. Preferably, for multiple executions of this program use
          the same store for the same device. The store directory can be shared
          between multiple different devices and users
          
          [default: /home/user/.local/share/matrix-commander-rs/store/]

      --login <LOGIN_METHOD>
          Login to and authenticate with the Matrix homeserver. Details:: This
          requires exactly one argument, the login method. Currently two
          choices are offered: 'password' and 'SSO'. Provide one of these
          methods. If you have chosen 'password', you will authenticate through
          your account password. You can optionally provide these additional
          arguments: --homeserver to specify the Matrix homeserver,
          --user-login to specify the log in user id, --password to specify the
          password, --device to specify a device name, --room-default to
          specify a default room for sending/listening. If you have chosen
          'SSO', you will authenticate through Single Sign-On. A web-browser
          will be started and you authenticate on the webpage. You can
          optionally provide these additional arguments: --homeserver to
          specify the Matrix homeserver, --user-login to specify the log in
          user id, --device to specify a device name, --room-default to specify
          a default room for sending/listening. See all the extra arguments for
          further explanations. ----- SSO (Single Sign-On) starts a web browser
          and connects the user to a web page on the server for login. SSO will
          only work if the server supports it and if there is access to a
          browser. So, don't use SSO on headless homeservers where there is no
          browser installed or accessible
          
          [default: none]

          Possible values:
          - none:         None: no login specified, don't login
          - password:     Password: login with password
          - access-token: AccessToken: login with access-token
          - sso:          SSO: login with SSO, single-sign on

      --verify <VERIFICATION_METHOD>
          Perform account verification. Details:: By default, no verification
          is performed. Verification is currently offered via Manual-Device,
          Manual-User, Emoji and Emoji-Req. Do verification in this order: 1)
          bottstrap first with -bootstrap, 2) perform both manual
          verifications, and 3) perform emoji verification. --verify emoji has
          been tested against Element in Firefox browser and against Element
          app on Android phone. Both has been working successfully in Sept
          2024. In Element web page it was important NOT to click the device in
          the device list, but to click the underscored link "Verify" just
          above the device list. In the Element on cell phone case, accept the
          emojis first on the cell phone. Manual verification is simpler but
          does less. Try: '--bootstrap --password mypassword --verify
          manual-device' or '--bootstrap --password mypassword --verify
          manual-user'. Manual only verfies devices or users one-directionally.
          See
          https://docs.rs/matrix-sdk/0.7/matrix_sdk/encryption/identities/struct.Device.html#method.verify
          and
          https://docs.rs/matrix-sdk/0.7/matrix_sdk/encryption/identities/struct.UserIdentity.html#method.verify
          for more info on Manual verification. manual-device can only verify
          its own devices, not other users' devices. manual-user can trust
          other users. So, with manual-user also use the --user option to
          specify one or multiple users. With manual-user first trust yourself,
          by setting --user to yourself, or omitting -user in which case it
          will default to itself. One should first do 'manual-device' and
          'manual-user' verification and then 'emoji' or 'emoji-req'
          verification. Both 'emoji' as well as 'emoji-req' perform emoji
          verification. With 'emoji' we send a request to some other client to
          request verification from their device. With 'emoji-req' we wait for
          some other client to request verification from us. If verification is
          desired, run this program in the foreground (not as a service) and
          without a pipe. While verification is optional it is highly
          recommended, and it is recommended to be done right after (or
          together with) the --login action. Verification is always
          interactive, i.e. it required keyboard input. Verification questions
          will be printed on stdout and the user has to respond via the
          keyboard to accept or reject verification. Once verification is
          complete, the program may be run as a service. Different Matrix
          clients (like Element app on cell phone, Element website in browser,
          other clients) have the "Verification" button hidden in different
          menus or GUI elements. Sometimes it is labelled "Not trusted",
          sometimes "Verify" or "Verify by emoji", sometimes "Verify With Other
          Device". Verification is best done as follows: Run
          'matrix-commander-rs --verify emoji ...' and have the program waiting
          for inputs and for invitations. Find the appropriate "verify" button
          on your other client, click it, and thereby publish a "verification
          invitation". Once received by "matrix-commander-rs" it will print the
          emojis in the terminal. At this point both your client as well as
          "matrix-commander-rs" in the terminal show a set of emoji icons and
          names. Compare them visually. Confirm on both sides (Yes, They Match,
          Got it), finally click OK. You should see a green shield and also see
          that the matrix-commander-rs device is now green and verified. In the
          terminal you should see a text message indicating success. It has
          been tested with Element app on cell phone and Element webpage in
          browser. Verification is done one device at a time. 'emoji-req' is
          similar. You must specify a user with --user and a device with
          --device to specify to which device you want to send the verification
          request. On the other device you get a pop up and you must accept the
          verification request. 'emoji-req' currently seems to have problems,
          while it does work with Element web page in browser, 'emoji-req' does
          not seem to work with Element phone app
          
          [default: none]

          Possible values:
          - none:          None: option not used, no verification done
          - manual-device: ManualDevice: manual device verification See also:
            https://docs.rs/matrix-sdk/0.7/matrix_sdk/encryption/identities/struct.Device.html#method.verify
          - manual-user:   ManualUser: manual user verification See also:
            https://docs.rs/matrix-sdk/0.7/matrix_sdk/encryption/identities/struct.UserIdentity.html#method.verify
          - emoji:         Emoji: verify via emojis as the recipient
          - emoji-req:     Emoji: verify via emojis as the initiator

      --bootstrap
          Details:: By default, no bootstrapping is performed. Bootstrapping is
          useful for verification. --bootstrap creates cross signing keys. If
          you have trouble verifying with --verify manual-device or --verify
          manual-user, use --bootstrap before. Use --password to provide
          password. If --password is not given it will read password from
          command line (stdin). See also
          https://docs.rs/matrix-sdk/0.7.1/matrix_sdk/encryption/struct.CrossSigningStatus.html#fields

      --logout <DEVICE>
          Logout this or all devices from the Matrix homeserver. Details:: This
          requires exactly one argument. Two choices are offered: 'me' and
          'all'. Provide one of these choices. If you choose 'me', only the one
          device "matrix-commander-rs" is currently using will be logged out.
          If you choose 'all', all devices of the user used by
          "matrix-commander-rs" will be logged out. Using '--logout all' is
          equivalent to '--delete-device "*" --logout "me"' and requires a
          password (see --delete-device). --logout not only logs the user out
          from the homeserver thereby invalidates the access token, it also
          removes both the 'credentials' file as well as the 'store' directory.
          After a --logout, one must perform a new --login to use
          "matrix-commander-rs" again. You can perfectly use
          "matrix-commander-rs" without ever logging out. --logout is a cleanup
          if you have decided not to use this (or all) device(s) ever again
          
          [default: none]

          Possible values:
          - none: None: Log out nowhere, don't do anything, default
          - me:   Me: Log out from the currently used device
          - all:  All: Log out from all devices of the user

      --homeserver <HOMESERVER>
          Specify a homeserver for use by certain actions. Details:: It is an
          optional argument. By default --homeserver is ignored and not used.
          It is used by '--login' action. If not provided for --login the user
          will be queried via keyboard

      --user-login <USER_LOGIN>
          Optional argument to specify the user for --login. Details:: This
          gives the otion to specify the user id for login. For '--login sso'
          the --user-login is not needed as user id can be obtained from server
          via SSO. For '--login password', if not provided it will be queried
          via keyboard. A full user id like '@john:example.com', a partial user
          name like '@john', and a short user name like 'john' can be given.
          --user-login is only used by --login and ignored by all other actions

      --password <PASSWORD>
          Specify a password for use by certain actions. Details:: It is an
          optional argument. By default --password is ignored and not used. It
          is used by '--login password' and '--delete-device' and --bootstrap
          actions. If not provided for --login, --delete-device or --bootstrap
          the user will be queried for the password via keyboard interactively

      --device <DEVICE>
          Specify a device name, for use by certain actions. Details:: It is an
          optional argument. By default --device is ignored and not used. It is
          used by '--login' action. If not provided for --login the user will
          be queried via keyboard. If you want the default value specify ''.
          Multiple devices (with different device id) may have the same device
          name. In short, the same device name can be assigned to multiple
          different devices if desired Don't confuse this option with
          '--devices'

      --room-default <ROOM_DEFAULT>
          Optionally specify a room as the default room for future actions.
          Details:: If not specified for --login, it will be queried via the
          keyboard. --login stores the specified room as default room in your
          credentials file. This option is only used in combination with
          --login. A default room is needed. Specify a valid room either with
          --room-default or provide it via keyboard

      --devices
          Print the list of devices. Details:: All device of this account will
          be printed, one device per line. Don't confuse this option with
          --device

      --timeout <TIMEOUT>
          Set the timeout of the calls to the Matrix server. Details:: By
          default they are set to 60 seconds. Specify the timeout in seconds.
          Use 0 for infinite timeout
          
          [default: 60]

  -m, --message [<MESSAGE>...]
          Send one or more messages. Details:: Message data must not be binary
          data, it must be text. Input piped via stdin can additionally be
          specified with the special character '-'. If you want to feed a text
          message into the program via a pipe, via stdin, then specify the
          special character '-'. If your message is literally a single letter
          '-' then use an escaped '\-' or a quoted "\-". Depending on your
          shell, '-' might need to be escaped. If this is the case for your
          shell, use the escaped '\-' instead of '-' and '\\-' instead of '\-'.
          However, depending on which shell you are using and if you are
          quoting with double quotes or with single quotes, you may have to add
          backslashes to achieve the proper escape sequences. If you want to
          read the message from the keyboard use '-' and do not pipe anything
          into stdin, then a message will be requested and read from the
          keyboard. Keyboard input is limited to one line. The stdin indicator
          '-' may appear in any position, i.e. -m 'start' '-' 'end' will send 3
          messages out of which the second one is read from stdin. The stdin
          indicator '-' may appear only once overall in all arguments. '-'
          reads everything that is in the pipe in one swoop and sends a single
          message. Similar to '-', another shortcut character is '_'. The
          special character '_' is used for streaming data via a pipe on stdin.
          With '_' the stdin pipe is read line-by-line and each line is treated
          as a separate message and sent right away. The program waits for pipe
          input until the pipe is closed. E.g. Imagine a tool that generates
          output sporadically 24x7. It can be piped, i.e. streamed, into
          matrix- commander, and matrix-commander stays active, sending all
          input instantly. If you want to send the literal letter '_' then
          escape it and send '\_'. '_' can be used only once. And either '-' or
          '_' can be used

      --markdown
          Specify the message format as MarkDown. Details:: There are 3 message
          formats for '--message'. Plain text, MarkDown, and Code. By default,
          if no command line options are specified, 'plain text' will be used.
          Use '--markdown' or '--code' to set the format to MarkDown or Code
          respectively. '--markdown' allows sending of text formatted in
          MarkDown language. '--code' allows sending of text as a Code block

      --code
          SPecify the message format as Code. Details:: There are 3 message
          formats for '--message'. Plain text, MarkDown, and Code. By default,
          if no command line options are specified, 'plain text' will be used.
          Use '--markdown' or '--code' to set the format to MarkDown or Code
          respectively. '--markdown' allows sending of text formatted in
          MarkDown language. '--code' allows sending of text as a Code block

  -r, --room [<ROOM>...]
          Optionally specify one or multiple rooms. Details:: Specify rooms via
          room ids or room aliases. '--room' is used by various options like
          '--message', '--file', some variants of '--listen',
          '--delete-device', etc. The default room is provided in the
          credentials file (specified at --login with --room-default). If a
          room (or multiple ones) is (or are) provided in the --room arguments,
          then it (or they) will be used instead of the one from the
          credentials file. The user must have access to the specified room in
          order to send messages there or listen on the room. Messages cannot
          be sent to arbitrary rooms. When specifying the room id some shells
          require the exclamation mark to be escaped with a backslash. Not all
          listen operations allow setting a room. Read more under the --listen
          options and similar. Most actions also support room aliases or local
          canonical short aliases instead of room ids. Using a room id is
          always faster than using a room alias

  -f, --file [<FILE>...]
          Send one or multiple files (e.g. PDF, DOC, MP4). Details:: First
          files are sent, then text messages are sent. If you want to feed a
          file into "matrix-commander-rs" via a pipe, via stdin, then specify
          the special character '-' as stdin indicator. See description of
          '--message' to see how the stdin indicator '-' is handled. If you
          pipe a file into stdin, you can optionally use '--file-name' to
          attach a label and indirectly a MIME type to the piped data. E.g. if
          you pipe in a PNG file, you might want to specify additionally
          '--file-name image.png'. As such, the label 'image' will be given to
          the data and the MIME type 'png' will be attached to it. Furthermore,
          '-' can only be used once

      --notice
          Specify the message type as Notice. Details:: There are 3 message
          types for '--message'. Text, Notice, and Emote. By default, if no
          command line options are specified, 'Text' will be used. Use
          '--notice' or '--emote' to set the type to Notice or Emote
          respectively. '--notice' allows sending of text as a notice.
          '--emote' allows sending of text as an emote

      --emote
          Specify the message type as Emote. Details:: There are 3 message
          types for '--message'. Text, Notice, and Emote. By default, if no
          command line options are specified, 'Text' will be used. Use
          '--notice' or '--emote' to set the type to Notice or Emote
          respectively. '--notice' allows sending of text as a notice.
          '--emote' allows sending of text as an emote

      --sync <SYNC_TYPE>
          Select synchronization choice. Details:: This option decides on
          whether the program synchronizes the state with the server before a
          'send' action. Currently two choices are offered: 'full' and 'off'.
          Provide one of these choices. The default is 'full'. If you want to
          use the default, then there is no need to use this option. If you
          have chosen 'full', the full state, all state events will be
          synchronized between this program and the server before a 'send'. If
          you have chosen 'off', synchronization will be skipped entirely
          before the 'send' which will improve performance
          
          [default: full]

          Possible values:
          - off:  Turns syncing off for sending operations to improve
            performance
          - full: full: the default value

  -l, --listen <LISTEN_TYPE>
          Listen to messages. Details:: The '--listen' option takes one
          argument. There are several choices: 'never', 'once', 'forever',
          'tail', and 'all'. By default, --listen is set to 'never'. So, by
          default no listening will be done. Set it to 'forever' to listen for
          and print incoming messages to stdout. '--listen forever' will listen
          to all messages on all rooms forever. To stop listening 'forever',
          use Control-C on the keyboard or send a signal to the process or
          service. '--listen once' will get all the messages from all rooms
          that are currently queued up. So, with 'once' the program will start,
          print waiting messages (if any) and then stop. The timeout for 'once'
          is set to 10 seconds. So, be patient, it might take up to that amount
          of time. 'tail' reads and prints the last N messages from the
          specified rooms, then quits. The number N can be set with the
          '--tail' option. With 'tail' some messages read might be old, i.e.
          already read before, some might be new, i.e. never read before. It
          prints the messages and then the program stops. Messages are sorted,
          last-first. Look at '--tail' as that option is related to '--listen
          tail'. The option 'all' gets all messages available, old and new.
          Unlike 'once' and 'forever' that listen in ALL rooms, 'tail' and
          'all' listen only to the room specified in the credentials file or
          the --room options
          
          [default: never]

          Possible values:
          - never:   Never: Indicates to not listen, default
          - once:    Once: Indicates to listen once in *all* rooms and then
            continue
          - forever: Forever: Indicates to listen forever in *all* rooms, until
            process is killed manually. This is the only option that remains in
            the event loop
          - tail:    Tail: Indicates to get the last N messages from the
            specified romm(s) and then continue
          - all:     All: Indicates to get *all* the messages from from the
            specified romm(s) and then continue

      --tail <TAIL>
          Get the last messages. Details:: The '--tail' option reads and prints
          up to the last N messages from the specified rooms, then quits. It
          takes one argument, an integer, which we call N here. If there are
          fewer than N messages in a room, it reads and prints up to N
          messages. It gets the last N messages in reverse order. It print the
          newest message first, and the oldest message last. If '--listen-self'
          is not set it will print less than N messages in many cases because N
          messages are obtained, but some of them are discarded by default if
          they are from the user itself. Look at '--listen' as this option is
          related to '--tail'
          
          [default: 0]

  -y, --listen-self
          Get your own messages. Details:: If set and listening, then program
          will listen to and print also the messages sent by its own user. By
          default messages from oneself are not printed

      --whoami
          Print your user name. Details:: Print the user id used by
          "matrix-commander-rs" (itself). One can get this information also by
          looking at the credentials file

  -o, --output <OUTPUT_FORMAT>
          Specify the output format. Details:: This option decides on how the
          output is presented. Currently offered choices are: 'text', 'json',
          'json-max', and 'json-spec'. Provide one of these choices. The
          default is 'text'. If you want to use the default, then there is no
          need to use this option. If you have chosen 'text', the output will
          be formatted with the intention to be consumed by humans, i.e.
          readable text. If you have chosen 'json', the output will be
          formatted as JSON. The content of the JSON object matches the data
          provided by the matrix-nio SDK. In some occassions the output is
          enhanced by having a few extra data items added for convenience. In
          most cases the output will be processed by other programs rather than
          read by humans. Option 'json-max' is practically the same as 'json',
          but yet another additional field is added. The data item
          'transport_response' which gives information on how the data was
          obtained and transported is also being added. For '--listen' a few
          more fields are added. In most cases the output will be processed by
          other programs rather than read by humans. Option 'json-spec' only
          prints information that adheres 1-to-1 to the Matrix Specification.
          Currently only the events on '--listen' and '--tail' provide data
          exactly as in the Matrix Specification. If no data is available that
          corresponds exactly with the Matrix Specification, no data will be
          printed. In short, currently '--json-spec' only provides outputs for
          '--listen' and '--tail'
          
          [default: text]

          Possible values:
          - text:      Text: Indicates to print human readable text, default
          - json:      Json: Indicates to print output in Json format
          - json-max:  Json Max: Indicates to to print the maximum anount of
            output in Json format
          - json-spec: Json Spec: Indicates to to print output in Json format,
            but only data that is according to Matrix Specifications

      --file-name [<FILE_NAME>...]
          Specify one or multiple file names for some actions. Details:: This
          is an optional argument. Use this option in combination with options
          like '--file'. to specify one or multiple file names. Ignored if used
          by itself without an appropriate corresponding action

      --get-room-info [<ROOM>...]
          Get room information. Details:: Get the room information such as room
          display name, room alias, room creator, etc. for one or multiple
          specified rooms. The included room 'display name' is also referred to
          as 'room name' or incorrectly even as room title. If one or more
          rooms are given, the room information of these rooms will be fetched.
          If no room is specified, nothing will be done. If you want the room
          information for the pre-configured default room specify the shortcut
          '-'. Rooms can be given via room id (e.g.
          '\!SomeRoomId:matrix.example.com'), canonical (full) room alias (e.g.
          '#SomeRoomAlias:matrix.example.com'), or short alias (e.g.
          'SomeRoomAlias' or '#SomeRoomAlias'). As response room id, room
          display name, room canonical alias, room topic, room creator, and
          room encryption are printed. One line per room will be printed. Since
          either room id or room alias are accepted as input and both room id
          and room alias are given as output, one can hence use this option to
          map from room id to room alias as well as vice versa from room alias
          to room id. Do not confuse this option with the options
          '--get-display-name' and '--set-display-name', which get/set the user
          display name, not the room display name. The argument
          '--room-resolve-alias' can also be used to go the other direction,
          i.e. to find the room id given a room alias

      --room-create [<LOCAL_ALIAS>...]
          Create one or multiple rooms. Details:: One or multiple room aliases
          can be specified. For each alias specified a room will be created.
          For each created room one line with room id, alias, name and topic
          will be printed to stdout. If you are not interested in an alias,
          provide an empty string like ''. The alias provided must be in
          canocial local form, i.e. if you want a final full alias like
          '#SomeRoomAlias:matrix.example.com' you must provide the string
          'SomeRoomAlias'. The user must be permitted to create rooms. Combine
          --room-create with --name and --topic to add names and topics to the
          room(s) to be created. If the output is in JSON format, then the
          values that are not set and hence have default values are not shown
          in the JSON output. E.g. if no topic is given, then there will be no
          topic field in the JSON output. Room aliases have to be unique

      --room-dm-create [<USER>...]
          Create one or multiple direct messaging (DM) rooms for given users.
          Details:: One or multiple users can be specified. For each user
          specified a DM room will be created. For each created DM room one
          line with room id, alias, name and topic will be printed to stdout.
          The given user(s) will receive an invitation to join the newly
          created room. The user must be permitted to create rooms. Combine
          --room-dm-create with --alias, --name and --topic to add aliases,
          names and topics to the room(s) to be created. Room aliases in
          --alias have to be unique

      --room-leave [<ROOM>...]
          Leave this room or these rooms. Details:: One or multiple room
          aliases can be specified. The room (or multiple ones) provided in the
          arguments will be left. You can run both commands '--room-leave' and
          '--room-forget' at the same time

      --room-forget [<ROOM>...]
          Forget one or multiple rooms. Details:: After leaving a room you
          should (most likely) forget the room. Forgetting a room removes the
          users' room history. One or multiple room aliases can be specified.
          The room (or multiple ones) provided in the arguments will be
          forgotten. If all users forget a room, the room can eventually be
          deleted on the server. You must leave a room first, before you can
          forget it You can run both commands '--room-leave' and
          '--room-forget' at the same time

      --room-invite [<ROOM>...]
          Invite one ore more users to join one or more rooms. Details::
          Specify the user(s) as arguments to --user. Specify the rooms as
          arguments to this option, i.e. as arguments to --room-invite. The
          user must have permissions to invite users. Use the shortcut '-' to
          specify the pre-configured default room of 'matrix-commander-rs' as
          room

      --room-join [<ROOM>...]
          Join one or multiple rooms. Details:: One or multiple room aliases
          can be specified. The room (or multiple ones) provided in the
          arguments will be joined. The user must have permissions to join
          these rooms. Use the shortcut '-' to specify the pre-configured
          default room of 'matrix-commander-rs' as room. Note, no --user on
          this feature as the user is always the user of 'matrix-commander-rs'

      --room-ban [<ROOM>...]
          Ban one ore more users from one or more rooms. Details:: Specify the
          user(s) as arguments to --user. Specify the rooms as arguments to
          this option, i.e. as arguments to --room-ban. The user must have
          permissions to ban users. Use the shortcut '-' to specify the
          pre-configured default room of 'matrix-commander-rs' as room

      --room-unban [<ROOM>...]
          Unban one ore more users from one or more rooms. Details:: Specify
          the user(s) as arguments to --user. Specify the rooms as arguments to
          this option, i.e. as arguments to --room-unban. The user must have
          permissions to unban users. Use the shortcut '-' to specify the
          pre-configured default room of 'matrix-commander-rs' as room. Note,
          this is currently not implemented in the matrix-sdk API. This feature
          will currently return an error

      --room-kick [<ROOM>...]
          Kick one ore more users from one or more rooms. Details:: Specify the
          user(s) as arguments to --user. Specify the rooms as arguments to
          this option, i.e. as arguments to --room-kick. The user must have
          permissions to kick users. Use the shortcut '-' to specify the
          pre-configured default room of 'matrix-commander-rs' as room

      --room-resolve-alias [<ALIAS>...]
          Resolves room aliases to room ids. Details:: Resolves a room alias to
          the corresponding room id, or multiple room aliases to their
          corresponding room ids. Provide one or multiple room aliases. A room
          alias looks like this: '#someRoomAlias:matrix.example.org'. Short
          aliases like 'someRoomAlias' or '#someRoomAlias' are also accepted.
          In case of a short alias, it will be automatically prefixed with '#'
          and the homeserver from the default room of matrix-commander-rs (as
          found in credentials file) will be automatically appended. Resolving
          an alias that does not exist results in an error. For each room alias
          one line will be printed to stdout with the result. It also prints
          the list of servers that know about the alias(es). The argument
          '--get-room-info' can be used to go the other direction, i.e. to find
          the room aliases given a room id

      --room-enable-encryption [<ROOM>...]
          Enable encryption for one or multiple rooms. Details:: Provide one or
          more room ids. For each room given encryption will be enabled. You
          must be member of the room in order to be able to enable encryption.
          Use shortcut '-' to enable encryption in the pre-configured default
          room. Enabling an already enabled room will do nothing and cause no
          error

      --alias [<ALIAS>...]
          Provide one or more aliases. Details:: --alias is currently used in
          combination with --room-dm-create. It is ignored otherwise. Canonical
          short alias look like 'SomeRoomAlias'. Short aliases look like
          '#SomeRoomAlias'. And full aliases look like
          '#SomeRoomAlias:matrix.example.com'. If you are not interested in an
          alias, provide an empty string like ''. Remember that aliases must be
          unique. For --room-dm-create you must provide canonical short
          alias(es)

      --name [<NAME>...]
          Specify one or multiple names. Details:: This option is only
          meaningful in combination with option --room-create. This option
          --name specifies the names to be used with the command --room-create

      --topic [<TOPIC>...]
          Specify one or multiple topics. Details:: This option is only
          meaningful in combination with option --room-create. This option
          --topic specifies the topics to be used with the command
          --room-create

      --rooms
          Print the list of past and current rooms. Details:: All rooms that
          you are currently a member of (joined rooms), that you had been a
          member of in the past (left rooms), and rooms that you have been
          invited to (invited rooms) will be printed, one room per line. See
          also '--invited-rooms', '--joined-rooms', and '--left-rooms'

      --invited-rooms
          Print the list of invited rooms. Details:: All rooms that you are
          currently invited to will be printed, one room per line

      --joined-rooms
          Print the list of joined rooms. Details:: All rooms that you are
          currently a member of will be printed, one room per line

      --left-rooms
          Print the list of left rooms. Details:: All rooms that you have left
          in the past will be printed, one room per line

      --room-get-visibility [<ROOM>...]
          Get the visibility of one or more rooms. Details:: Provide one or
          more room ids as arguments. If the shortcut '-' is used, then the
          default room of 'matrix-commander-rs' (as found in credentials file)
          will be used. The shortcut '*' represents all the rooms of the user
          of 'matrix-commander-rs'. For each room the visibility will be
          printed. Currently, this is either the string 'private' or 'public'.
          As response one line per room will be printed

      --room-get-state [<ROOM>...]
          Get the state of one or more rooms. Details:: Provide one or more
          room ids as arguments. If the shortcut '-' is used, then the default
          room of 'matrix-commander-rs' (as found in credentials file) will be
          used. The shortcut '*' represents all the rooms of the user of
          'matrix-commander-rs'. For each room part of the state will be
          printed. The state is a long list of events. As response one line per
          room will be printed to stdout. The line can be very long as the list
          of events can be very large. To get output into a human readable form
          pipe output through sed and jq or use the JSON output

      --joined-members [<ROOM>...]
          Print the list of joined members for one or multiple rooms. Details::
          If you want to print the joined members of all rooms that you are
          member of, then use the special shortcut character '*'. If you want
          the members of the pre-configured default room, use shortcut '-'

      --delete-device [<DEVICE>...]
          Delete one or multiple devices. Details:: By default devices
          belonging to itself, i.e. belonging to "matrix-commander-rs", will be
          deleted. If you want to delete the one device currently used for the
          connection, i.e. the device used by "matrix-commander-rs", then
          instead of the full device id you can just specify the shortcut 'me'
          such as '--delete-device me --password mypassword'. If you want to
          delete all devices of yourself, i.e. all devices owned by the user
          that "matrix-commander-rs" is using you can specify that with the
          shortcut '*'. Most shells require you to escape it or to quote it,
          ie. use '--delete-device "*" --password mypassword'. Removing your
          own device (e.g. 'me') or all devices (e.g. '*') will require you to
          manually remove your credentials file and store directory and to
          login anew in order to create a new device. If you are using
          '--delete-device me --password mypassword' consider using '--logout
          me' instead which is simpler (no password) and also automatically
          performs the removal of credentials and store. (See --logout.) If the
          devices belong to a different user, use the --user argument to
          specify the user, i.e. owner. Only exactly one user can be specified
          with the optional --user argument. Device deletion requires the user
          password. It must be specified with the --password argument. If the
          server uses only HTTP (and not HTTPS), then the password can be
          visible to attackers. Hence, if the server does not support HTTPS
          this operation is discouraged. If no --password is specified via the
          command line, the password is read from keyboard interactively

  -u, --user [<USER>...]
          Specify one or multiple users. Details:: This option is meaningful in
          combination with a) room actions like --room-invite, --room-ban,
          --room-unban, etc. and d) actions like --delete-device. In case of a)
          this option --user specifies the users to be used with room commands
          (like invite, ban, For d) this gives the option to delete the device
          of a different user. If --user is not set, it will default to itself,
          i.e. the user of the "matrix-commander-rs" account

      --get-avatar <FILE>
          Get your own avatar. Details:: Get the avatar of itself, i.e. the
          'matrix-commander-rs' user account. Spefify a file optionally with
          path to store the image. E.g. --get-avatar "./avatar.png"

      --set-avatar <FILE>
          Set your own avatar. Details:: Set, i.e. upload, an image to be used
          as avatar for 'matrix-commander-rs' user account. Spefify a file
          optionally with path with the image. If the MIME type of the image
          cannot be determined, it will assume 'PNG' as default. E.g.
          --set-avatar "./avatar.jpg". It returns a line with the MRX URI of
          the new avatar

      --get-avatar-url
          Get your own avatar URL. Details:: Get the MXC URI of the avatar of
          itself, i.e. the 'matrix-commander-rs' user account

      --set-avatar-url <MAX_URI>
          Set your own avatar URL. Details:: Set the avatar MXC URI of the URL
          to be used as avatar for the 'matrix-commander-rs' user account.
          Spefify a MXC URI. E.g. --set-avatar-url
          "mxc://matrix.server.org/SomeStrangeStringOfYourMxcUri"

      --unset-avatar-url
          Remove your own avatar URL. Details:: Remove the avatar MXC URI to be
          used as avatar for the 'matrix-commander-rs' user account. In other
          words, remove the avatar of the 'matrix-commander-rs' user

      --get-display-name
          Get your own display name. Details:: Get the display name of itself,
          i.e. of the 'matrix-commander-rs' user account

      --set-display-name <NAME>
          Set your own display name. Details:: Set the display name of the
          'matrix-commander-rs' user account. Spefify a name

      --get-profile
          Get your own profile. Details:: Get the profile of itself, i.e. of
          the 'matrix-commander-rs' user account. This is getting both display
          name and avatar MXC URI in a call

      --media-upload [<FILE>...]
          Upload one or multiple files (e.g. PDF, DOC, MP4) to the homeserver
          content repository. Details:: If you want to feed a file for upload
          into "matrix-commander-rs" via a pipe, via stdin, then specify the
          special character '-' as stdin indicator. See description of
          '--message' to see how the stdin indicator '-' is handled. Use --mime
          to optionally specify the MIME type of the file. If you give N
          arguments to --media-upload, you can give N arguments to --mime. See
          --mime. If you pipe a file into stdin, the MIME type cannot be
          guessed. It is hence more recommended that you specify a MIME type
          via '--mime' when using '-'. Furthermore, '-' can only be used once.
          Upon being stored in the homeserver's content repository, the data is
          assigned a Matrix MXC URI. For each file uploaded successfully, a
          single line with the MXC URI will be printed. The uploaded data will
          not by encrypted. If you want to upload encrypted data, encrypt the
          file before uploading it

      --media-download [<MXC_URI>...]
          Download one or multiple files from the homeserver content
          repository. Details:: You must provide one or multiple Matrix URIs
          (MXCs) which are strings like this
          'mxc://example.com/SomeStrangeUriKey'. Alternatively, you can just
          provide the MXC id, i.e. the part after the last slash. If found they
          will be downloaded, decrypted, and stored in local files. If file
          names are specified with --file-name the downloads will be saved with
          these file names. If --file-name is not specified, then the file name
          'mxc-<mxc-id>' will be used. If a file name in --file-name contains
          the placeholder __mxc_id__, it will be replaced with the mxc-id. If a
          file name is specified as empty string '' in --file-name, then also
          the name 'mxc-<mxc-id>' will be used. Be careful, existing files will
          be overwritten. Do not confuse --media-download with
          --download-media. See --download-media

      --mime [<MIME_TYPE>...]
          Specify the Mime type of certain input files. Details:: Specify '' if
          the Mime type should be guessed based on the filename. If input is
          from stdin (i.e. '-' and piped into 'matrix-commander-rs') then Mime
          type cannot be guessed. If not specified, and no filename available
          for guessing it will default to 'application/octet-stream'. Some
          example mime types are: 'image/jpeg', 'image/png', 'image/gif',
          'text/plain', and 'application/pdf'. For a full list see
          'https://docs.rs/mime/latest/mime/#constants'

      --media-delete [<MXC_URI>...]
          Delete one or multiple objects (e.g. files) from the content
          repository. Details:: You must provide one or multiple Matrix URIs
          (MXC) which are strings like this
          'mxc://example.com/SomeStrangeUriKey'. Alternatively, you can just
          provide the MXC id, i.e. the part after the last slash. If found they
          will be deleted from the server database. In order to delete objects
          one must have server admin permissions. Having only room admin
          permissions is not sufficient and it will fail. Read
          https://matrix-org.github.io/synapse/latest/usage/administration/admin_api/
          for learning how to set server admin permissions on the server.
          Thumbnails will currently not be deleted. Deleting something that
          does not exist will be ignored and will not cause an error

      --media-mxc-to-http [<MXC_URI>...]
          Convert URIs to HTTP URLs. Details:: Convert one or more matrix
          content URIs to the corresponding HTTP URLs. The MXC URIs to provide
          look something like this 'mxc://example.com/SomeStrangeUriKey'.
          Alternatively, you can just provide the MXC id, i.e. the part after
          the last slash. The syntax of the provided MXC URIs will be verified.
          The existance of content for the XMC URI will not be checked

      --get-masterkey
          Get your own master key. Details:: Get the master key of itself, i.e.
          of the 'matrix-commander-rs' user account. Keep this key private and
          safe

PS: Also have a look at scripts/matrix-commander-rs-tui.

```
