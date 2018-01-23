from jarjar import jarjar


def send2slack(webhook_url='', channel='', msg=''):
    if webhook_url is '' or msg is '' or channel is '':
        raise ValueError("Can't notify slack without a message, webhook and channel")

    webhook = webhook_url
    channel = channel
    msg = msg

    jarjar(webhook=webhook, channel=channel).text(msg)


