class Reorder:
    def __init__(self, tun, wsize, trigger=15):
        self.next_buffer_id_expected = 0

        self.tun = tun
        self.wsize = wsize
        self.trigger = trigger

        self.buf = {}

    def increment(self,start=None):
        if start is None:
            self.next_buffer_id_expected += 1
        else:
            self.next_buffer_id_expected = start + 1

        if self.next_buffer_id_expected >= self.wsize: self.next_buffer_id_expected = 0

    def incoming(self, buffer_id, data):
        if self.trigger == 0:#option to essentially turn this off
            self.tun.write(data)
            return


        if buffer_id < self.next_buffer_id_expected:
            self.tun.write(data)
            # print("b",end='')
        else:
            self.buf[buffer_id] = data

        while self.next_buffer_id_expected in self.buf:
            self.tun.write(self.buf[self.next_buffer_id_expected])
            # print("a", end='')
            try:
                del self.buf[self.next_buffer_id_expected]
            except:
                pass
            self.increment()

        if len(self.buf) > self.trigger:
            self.empty_buffer()

        return


    def empty_buffer(self):
        keys = sorted(self.buf.keys())
        for k in keys:
            self.tun.write(self.buf[k])
            # print("c",end='')
            try:
                del self.buf[k]
            except:
                pass
        if len(keys) > 0:
            self.increment(start=max(keys))
