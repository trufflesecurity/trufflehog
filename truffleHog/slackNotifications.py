from jarjar import jarjar


def send2slack(webhook_url='', channel='', msg=''):
    webhook = webhook_url
    channel = channel
    msg = msg

    jj = jarjar(webhook=webhook, channel=channel)
    jj.text(msg)
