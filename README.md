# dhttpr

lightweight, insecure, incomplete web server

I wrote this just to see if I could; I actually found a use for it as a
super-lightweight, almost-dependencyless way to test web stuff locally.
I don't have to setup and configure Apache or Hiawatha or whatever on my
laptop just to see if some CSS I'm tweaking works.

The only dependency is [`inetd`](https://en.wikipedia.org/wiki/Inetd)
(or a workalike--I use [`xinetd`](https://en.wikipedia.org/wiki/Xinetd)).


## Installation & Configuration

Clone the repository and edit the user-configurable variables at the top
of `dhttpd.py`. You can probably get away with only editing the
`INSTALL_DIR`, and it will still work out of the box. (If your system's
temporary files aren't stored in `/tmp`, and you don't have a `/run/shm`,
you may need to probe deeper, and also poke around in `dhttpr.py`.)

The only other thing you need to do is configure `inetd`. Here's a sample
configuration stanza:

```
service http
{
    disable     = no
    port        = 80
    flags       = REUSE
    protocol    = tcp
    socket_type = stream
    wait        = no
    user        = dan
    server      = /home/dan/dev/dhttpr/dhttpr.py
}
```

Launch it with `nohup`:

    dan@dante:~/dev/dhttpr$ nohup python dhttpd.py &

and it'll run until you echo `EXIT` down its control pipe

    dan@dante:~/dev/dhttpr$ echo "EXIT" >/run/shm/dhttpr/input

or until it crashes. ;^)


## Issues

It only serves `GET` and `POST` requests, and the way it serves `POST`s
is still a little hacky. It also gets tripped up if you point it at a
directory without manually appending a trailing slash (`/`) to the URL.

As stated before, it's, like, totally without security, or any features
other than directly responding to `GET`s and `POST`s. No request throttling
(except as limited by the hardware and `dhttpd.py`'s ability to process
requests serially). It was meant to be educational (for me), and to a lesser
degree a simple local tool for determining if your web layouts look good
(I guess).
