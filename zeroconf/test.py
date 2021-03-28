#!/usr/bin/env python
# -*- coding: utf-8 -*-


""" Unit tests for zeroconf.py """

import copy
import logging
import os
import platform
import socket
import struct
import threading
import time
import unittest
import six
from six import indexbytes, int2byte

try:
    import unittest.mock as mock
except ImportError:
    import mock

from threading import Event

import pytest

import zeroconf as r
from zeroconf import (
    DNSHinfo,
    DNSText,
    ServiceBrowser,
    ServiceInfo,
    ServiceStateChange,
    Zeroconf,
    ZeroconfServiceTypes,
    _EXPIRE_REFRESH_TIME_PERCENT,
)

log = logging.getLogger('zeroconf')
original_logging_level = logging.NOTSET


def setup_module():
    global original_logging_level
    original_logging_level = log.level
    log.setLevel(logging.DEBUG)


def teardown_module():
    if original_logging_level != logging.NOTSET:
        log.setLevel(original_logging_level)


class TestDunder(unittest.TestCase):
    def test_dns_text_repr(self):
        # There was an issue on Python 3 that prevented DNSText's repr
        # from working when the text was longer than 10 bytes
        text = DNSText('irrelevant', 0, 0, 0, b'12345678901')
        repr(text)

        text = DNSText('irrelevant', 0, 0, 0, b'123')
        repr(text)

    def test_dns_hinfo_repr_eq(self):
        hinfo = DNSHinfo('irrelevant', r._TYPE_HINFO, 0, 0, 'cpu', 'os')
        assert hinfo == hinfo
        repr(hinfo)

    def test_dns_pointer_repr(self):
        pointer = r.DNSPointer('irrelevant', r._TYPE_PTR, r._CLASS_IN, r._DNS_OTHER_TTL, '123')
        repr(pointer)

    def test_dns_address_repr(self):
        address = r.DNSAddress('irrelevant', r._TYPE_SOA, r._CLASS_IN, 1, b'a')
        assert repr(address).endswith("a")

        address_ipv4 = r.DNSAddress(
            'irrelevant', r._TYPE_SOA, r._CLASS_IN, 1, socket.inet_pton(socket.AF_INET, '127.0.0.1')
        )
        assert repr(address_ipv4).endswith('127.0.0.1')

        address_ipv6 = r.DNSAddress(
            'irrelevant', r._TYPE_SOA, r._CLASS_IN, 1, socket.inet_pton(socket.AF_INET6, '::1')
        )
        assert repr(address_ipv6).endswith('::1')

    def test_dns_question_repr(self):
        question = r.DNSQuestion('irrelevant', r._TYPE_SRV, r._CLASS_IN | r._CLASS_UNIQUE)
        repr(question)
        assert not question != question

    def test_dns_service_repr(self):
        service = r.DNSService('irrelevant', r._TYPE_SRV, r._CLASS_IN, r._DNS_HOST_TTL, 0, 0, 80, 'a')
        repr(service)

    def test_dns_record_abc(self):
        record = r.DNSRecord('irrelevant', r._TYPE_SRV, r._CLASS_IN, r._DNS_HOST_TTL)
        self.assertRaises(r.AbstractMethodException, record.__eq__, record)
        self.assertRaises(r.AbstractMethodException, record.write, None)

    def test_dns_record_reset_ttl(self):
        record = r.DNSRecord('irrelevant', r._TYPE_SRV, r._CLASS_IN, r._DNS_HOST_TTL)
        time.sleep(1)
        record2 = r.DNSRecord('irrelevant', r._TYPE_SRV, r._CLASS_IN, r._DNS_HOST_TTL)
        now = r.current_time_millis()

        assert record.created != record2.created
        assert record.get_remaining_ttl(now) != record2.get_remaining_ttl(now)

        record.reset_ttl(record2)

        assert record.ttl == record2.ttl
        assert record.created == record2.created
        assert record.get_remaining_ttl(now) == record2.get_remaining_ttl(now)

    def test_service_info_dunder(self):
        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)
        info = ServiceInfo(
            type_,
            registration_name,
            80,
            0,
            0,
            b'',
            "ash-2.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
        )

        assert not info != info
        repr(info)

    def test_service_info_text_properties_not_given(self):
        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)
        info = ServiceInfo(
            type_=type_,
            name=registration_name,
            addresses=[socket.inet_aton("10.0.1.2")],
            port=80,
            server="ash-2.local.",
        )

        assert isinstance(info.text, bytes)
        repr(info)

    def test_dns_outgoing_repr(self):
        dns_outgoing = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        repr(dns_outgoing)


class PacketGeneration(unittest.TestCase):
    def test_parse_own_packet_simple(self):
        generated = r.DNSOutgoing(0)
        r.DNSIncoming(generated.packet())

    def test_parse_own_packet_simple_unicast(self):
        generated = r.DNSOutgoing(0, False)
        r.DNSIncoming(generated.packet())

    def test_parse_own_packet_flags(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        r.DNSIncoming(generated.packet())

    def test_parse_own_packet_question(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        generated.add_question(r.DNSQuestion("testname.local.", r._TYPE_SRV, r._CLASS_IN))
        r.DNSIncoming(generated.packet())

    def test_parse_own_packet_response(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        generated.add_answer_at_time(
            r.DNSService(
                u"æøå.local.",
                r._TYPE_SRV,
                r._CLASS_IN | r._CLASS_UNIQUE,
                r._DNS_HOST_TTL,
                0,
                0,
                80,
                "foo.local.",
            ),
            0,
        )
        parsed = r.DNSIncoming(generated.packet())
        assert len(generated.answers) == 1
        assert len(generated.answers) == len(parsed.answers)

    def test_match_question(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        question = r.DNSQuestion("testname.local.", r._TYPE_SRV, r._CLASS_IN)
        generated.add_question(question)
        parsed = r.DNSIncoming(generated.packet())
        assert len(generated.questions) == 1
        assert len(generated.questions) == len(parsed.questions)
        assert question == parsed.questions[0]

    def test_suppress_answer(self):
        query_generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        question = r.DNSQuestion("testname.local.", r._TYPE_SRV, r._CLASS_IN)
        query_generated.add_question(question)
        answer1 = r.DNSService(
            "testname1.local.",
            r._TYPE_SRV,
            r._CLASS_IN | r._CLASS_UNIQUE,
            r._DNS_HOST_TTL,
            0,
            0,
            80,
            "foo.local.",
        )
        staleanswer2 = r.DNSService(
            "testname2.local.",
            r._TYPE_SRV,
            r._CLASS_IN | r._CLASS_UNIQUE,
            r._DNS_HOST_TTL / 2,
            0,
            0,
            80,
            "foo.local.",
        )
        answer2 = r.DNSService(
            "testname2.local.",
            r._TYPE_SRV,
            r._CLASS_IN | r._CLASS_UNIQUE,
            r._DNS_HOST_TTL,
            0,
            0,
            80,
            "foo.local.",
        )
        query_generated.add_answer_at_time(answer1, 0)
        query_generated.add_answer_at_time(staleanswer2, 0)
        query = r.DNSIncoming(query_generated.packet())

        # Should be suppressed
        response = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        response.add_answer(query, answer1)
        assert len(response.answers) == 0

        # Should not be suppressed, TTL in query is too short
        response.add_answer(query, answer2)
        assert len(response.answers) == 1

        # Should not be suppressed, name is different
        tmp = copy.copy(answer1)
        tmp.name = "testname3.local."
        response.add_answer(query, tmp)
        assert len(response.answers) == 2

        # Should not be suppressed, type is different
        tmp = copy.copy(answer1)
        tmp.type = r._TYPE_A
        response.add_answer(query, tmp)
        assert len(response.answers) == 3

        # Should not be suppressed, class is different
        tmp = copy.copy(answer1)
        tmp.class_ = r._CLASS_NONE
        response.add_answer(query, tmp)
        assert len(response.answers) == 4

        # ::TODO:: could add additional tests for DNSAddress, DNSHinfo, DNSPointer, DNSText, DNSService

    def test_dns_hinfo(self):
        generated = r.DNSOutgoing(0)
        generated.add_additional_answer(DNSHinfo('irrelevant', r._TYPE_HINFO, 0, 0, 'cpu', 'os'))
        parsed = r.DNSIncoming(generated.packet())
        answer = parsed.answers[0]
        assert answer.cpu == u'cpu'
        assert answer.os == u'os'

        generated = r.DNSOutgoing(0)
        generated.add_additional_answer(DNSHinfo('irrelevant', r._TYPE_HINFO, 0, 0, 'cpu', 'x' * 257))
        self.assertRaises(r.NamePartTooLongException, generated.packet)


class PacketForm(unittest.TestCase):
    def test_transaction_id(self):
        """ID must be zero in a DNS-SD packet"""
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        bytes = generated.packet()
        id = indexbytes(bytes, 0) << 8 | indexbytes(bytes, 1)
        assert id == 0

    def test_query_header_bits(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        bytes = generated.packet()
        flags = indexbytes(bytes, 2) << 8 | indexbytes(bytes, 3)
        assert flags == 0x0

    def test_response_header_bits(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        bytes = generated.packet()
        flags = indexbytes(bytes, 2) << 8 | indexbytes(bytes, 3)
        assert flags == 0x8000

    def test_numbers(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        bytes = generated.packet()
        (num_questions, num_answers, num_authorities, num_additionals) = struct.unpack('!4H', bytes[4:12])
        assert num_questions == 0
        assert num_answers == 0
        assert num_authorities == 0
        assert num_additionals == 0

    def test_numbers_questions(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion("testname.local.", r._TYPE_SRV, r._CLASS_IN)
        for i in range(10):
            generated.add_question(question)
        bytes = generated.packet()
        (num_questions, num_answers, num_authorities, num_additionals) = struct.unpack('!4H', bytes[4:12])
        assert num_questions == 10
        assert num_answers == 0
        assert num_authorities == 0
        assert num_additionals == 0


class Names(unittest.TestCase):
    def test_long_name(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion(
            "this.is.a.very.long.name.with.lots.of.parts.in.it.local.", r._TYPE_SRV, r._CLASS_IN
        )
        generated.add_question(question)
        r.DNSIncoming(generated.packet())

    def test_exceedingly_long_name(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        name = "%slocal." % ("part." * 1000)
        question = r.DNSQuestion(name, r._TYPE_SRV, r._CLASS_IN)
        generated.add_question(question)
        r.DNSIncoming(generated.packet())

    def test_extra_exceedingly_long_name(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        name = "%slocal." % ("part." * 4000)
        question = r.DNSQuestion(name, r._TYPE_SRV, r._CLASS_IN)
        generated.add_question(question)
        r.DNSIncoming(generated.packet())

    def test_exceedingly_long_name_part(self):
        name = "%s.local." % ("a" * 1000)
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion(name, r._TYPE_SRV, r._CLASS_IN)
        generated.add_question(question)
        self.assertRaises(r.NamePartTooLongException, generated.packet)

    def test_same_name(self):
        name = "paired.local."
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion(name, r._TYPE_SRV, r._CLASS_IN)
        generated.add_question(question)
        generated.add_question(question)
        r.DNSIncoming(generated.packet())

    def test_lots_of_names(self):

        # instantiate a zeroconf instance
        zc = Zeroconf(interfaces=['127.0.0.1'])

        # create a bunch of servers
        type_ = "_my-service._tcp.local."
        name = 'a wonderful service'
        server_count = 300
        self.generate_many_hosts(zc, type_, name, server_count)

        # verify that name changing works
        self.verify_name_change(zc, type_, name, server_count)

        # we are going to monkey patch the zeroconf send to check packet sizes
        old_send = zc.send

        class TestCtx(object):
            def __init__(self):
                self.longest_packet_len = 0
                self.longest_packet = None
        testCtx = TestCtx()

        def send(out, addr=r._MDNS_ADDR, port=r._MDNS_PORT):
            """Sends an outgoing packet."""
            for packet in out.packets():
                if testCtx.longest_packet_len < len(packet):
                    testCtx.longest_packet_len= len(packet)
                    testCtx.longest_packet = out
                old_send(out, addr=addr, port=port)

        # monkey patch the zeroconf send
        setattr(zc, "send", send)

        # dummy service callback
        def on_service_state_change(zeroconf, service_type, state_change, name):
            pass

        # start a browser
        browser = ServiceBrowser(zc, type_, [on_service_state_change])

        # wait until the browse request packet has maxed out in size
        sleep_count = 0
        # we will never get to this large of a packet given the application-layer
        # splitting of packets, but we still want to track the longest_packet_len
        # for the debug message below
        while sleep_count < 100 and testCtx.longest_packet_len < r._MAX_MSG_ABSOLUTE - 100:
            sleep_count += 1
            time.sleep(0.1)

        browser.cancel()
        time.sleep(0.5)

        import zeroconf

        zeroconf.log.debug('sleep_count %d, sized %d', sleep_count, testCtx.longest_packet_len)

        # now the browser has sent at least one request, verify the size
        assert testCtx.longest_packet_len <= r._MAX_MSG_TYPICAL
        assert testCtx.longest_packet_len >= r._MAX_MSG_TYPICAL - 100

        # mock zeroconf's logger warning() and debug()
        patch_warn = mock.patch('zeroconf.log.warning')
        patch_debug = mock.patch('zeroconf.log.debug')
        mocked_log_warn = patch_warn.start()
        mocked_log_debug = patch_debug.start()

        # now that we have a long packet in our possession, let's verify the
        # exception handling.
        out = testCtx.longest_packet
        assert out is not None
        out.data.append(b'\0' * 1000)

        # mock the zeroconf logger and check for the correct logging backoff
        call_counts = mocked_log_warn.call_count, mocked_log_debug.call_count
        # try to send an oversized packet
        zc.send(out)
        assert mocked_log_warn.call_count == call_counts[0]
        zc.send(out)
        assert mocked_log_warn.call_count == call_counts[0]

        # force a receive of a packet
        packet = out.packet()
        s = zc._respond_sockets[0]

        # mock the zeroconf logger and check for the correct logging backoff
        call_counts = mocked_log_warn.call_count, mocked_log_debug.call_count
        # force receive on oversized packet
        s.sendto(packet, 0, (r._MDNS_ADDR, r._MDNS_PORT))
        s.sendto(packet, 0, (r._MDNS_ADDR, r._MDNS_PORT))
        time.sleep(2.0)
        zeroconf.log.debug(
            'warn %d debug %d was %s', mocked_log_warn.call_count, mocked_log_debug.call_count, call_counts
        )
        assert mocked_log_debug.call_count > call_counts[0]

        # close our zeroconf which will close the sockets
        zc.close()

        # pop the big chunk off the end of the data and send on a closed socket
        out.data.pop()
        zc._GLOBAL_DONE = False

        # mock the zeroconf logger and check for the correct logging backoff
        call_counts = mocked_log_warn.call_count, mocked_log_debug.call_count
        # send on a closed socket (force a socket error)
        zc.send(out)
        zeroconf.log.debug(
            'warn %d debug %d was %s', mocked_log_warn.call_count, mocked_log_debug.call_count, call_counts
        )
        assert mocked_log_warn.call_count > call_counts[0]
        assert mocked_log_debug.call_count > call_counts[0]
        zc.send(out)
        zeroconf.log.debug(
            'warn %d debug %d was %s', mocked_log_warn.call_count, mocked_log_debug.call_count, call_counts
        )
        assert mocked_log_debug.call_count > call_counts[0] + 2

        mocked_log_warn.stop()
        mocked_log_debug.stop()

    def verify_name_change(self, zc, type_, name, number_hosts):
        desc = {'path': '/~paulsm/'}
        info_service = ServiceInfo(
            type_,
            '%s.%s' % (name, type_),
            80,
            0,
            0,
            desc,
            "ash-2.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
        )

        # verify name conflict
        self.assertRaises(r.NonUniqueNameException, zc.register_service, info_service)

        # verify no name conflict https://tools.ietf.org/html/rfc6762#section-6.6
        zc.register_service(info_service, cooperating_responders=True)

        zc.register_service(info_service, allow_name_change=True)
        assert info_service.name.split('.')[0] == '%s-%d' % (name, number_hosts + 1)

    def generate_many_hosts(self, zc, type_, name, number_hosts):
        records_per_server = 2
        block_size = 25
        number_hosts = int(((number_hosts - 1) / block_size + 1)) * block_size
        for i in range(1, number_hosts + 1):
            next_name = name if i == 1 else '%s-%d' % (name, i)
            self.generate_host(zc, next_name, type_)
            if i % block_size == 0:
                sleep_count = 0
                while sleep_count < 40 and i * records_per_server > len(zc.cache.entries_with_name(type_)):
                    sleep_count += 1
                    time.sleep(0.05)

    @staticmethod
    def generate_host(zc, host_name, type_):
        name = '.'.join((host_name, type_))
        out = r.DNSOutgoing(r._FLAGS_QR_RESPONSE | r._FLAGS_AA)
        out.add_answer_at_time(r.DNSPointer(type_, r._TYPE_PTR, r._CLASS_IN, r._DNS_OTHER_TTL, name), 0)
        out.add_answer_at_time(
            r.DNSService(type_, r._TYPE_SRV, r._CLASS_IN | r._CLASS_UNIQUE, r._DNS_HOST_TTL, 0, 0, 80, name),
            0,
        )
        zc.send(out)


class Framework(unittest.TestCase):
    def test_launch_and_close(self):
        rv = r.Zeroconf(interfaces=r.InterfaceChoice.All)
        rv.close()
        rv = r.Zeroconf(interfaces=r.InterfaceChoice.Default)
        rv.close()

    @unittest.skipIf(not socket.has_ipv6, 'Requires IPv6')
    @unittest.skipIf(os.environ.get('SKIP_IPV6'), 'IPv6 tests disabled')
    def test_launch_and_close_v4_v6(self):
        rv = r.Zeroconf(interfaces=r.InterfaceChoice.All, ip_version=r.IPVersion.All)
        rv.close()
        rv = r.Zeroconf(interfaces=r.InterfaceChoice.Default, ip_version=r.IPVersion.All)
        rv.close()

    @unittest.skipIf(not socket.has_ipv6, 'Requires IPv6')
    @unittest.skipIf(os.environ.get('SKIP_IPV6'), 'IPv6 tests disabled')
    def test_launch_and_close_v6_only(self):
        rv = r.Zeroconf(interfaces=r.InterfaceChoice.All, ip_version=r.IPVersion.V6Only)
        rv.close()
        rv = r.Zeroconf(interfaces=r.InterfaceChoice.Default, ip_version=r.IPVersion.V6Only)
        rv.close()

    def test_handle_response(self):
        def mock_incoming_msg(service_state_change):
            ttl = 120
            generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)

            if service_state_change == r.ServiceStateChange.Updated:
                generated.add_answer_at_time(
                    r.DNSText(service_name, r._TYPE_TXT, r._CLASS_IN | r._CLASS_UNIQUE, ttl, service_text), 0
                )
                return r.DNSIncoming(generated.packet())

            if service_state_change == r.ServiceStateChange.Removed:
                ttl = 0

            generated.add_answer_at_time(
                r.DNSPointer(service_type, r._TYPE_PTR, r._CLASS_IN, ttl, service_name), 0
            )
            generated.add_answer_at_time(
                r.DNSService(
                    service_name, r._TYPE_SRV, r._CLASS_IN | r._CLASS_UNIQUE, ttl, 0, 0, 80, service_server
                ),
                0,
            )
            generated.add_answer_at_time(
                r.DNSText(service_name, r._TYPE_TXT, r._CLASS_IN | r._CLASS_UNIQUE, ttl, service_text), 0
            )
            generated.add_answer_at_time(
                r.DNSAddress(
                    service_server,
                    r._TYPE_A,
                    r._CLASS_IN | r._CLASS_UNIQUE,
                    ttl,
                    socket.inet_aton(service_address),
                ),
                0,
            )

            return r.DNSIncoming(generated.packet())

        service_name = 'name._type._tcp.local.'
        service_type = '_type._tcp.local.'
        service_server = 'ash-2.local.'
        service_text = b'path=/~paulsm/'
        service_address = '10.0.1.2'

        zeroconf = r.Zeroconf(interfaces=['127.0.0.1'])

        try:
            # service added
            zeroconf.handle_response(mock_incoming_msg(r.ServiceStateChange.Added))
            dns_text = zeroconf.cache.get_by_details(service_name, r._TYPE_TXT, r._CLASS_IN)
            assert dns_text is not None
            assert dns_text.text == service_text  # service_text is b'path=/~paulsm/'

            # https://tools.ietf.org/html/rfc6762#section-10.2
            # Instead of merging this new record additively into the cache in addition
            # to any previous records with the same name, rrtype, and rrclass,
            # all old records with that name, rrtype, and rrclass that were received
            # more than one second ago are declared invalid,
            # and marked to expire from the cache in one second.
            time.sleep(1.1)

            # service updated. currently only text record can be updated
            service_text = b'path=/~humingchun/'
            zeroconf.handle_response(mock_incoming_msg(r.ServiceStateChange.Updated))
            dns_text = zeroconf.cache.get_by_details(service_name, r._TYPE_TXT, r._CLASS_IN)
            assert dns_text is not None
            assert dns_text.text == service_text  # service_text is b'path=/~humingchun/'

            time.sleep(1.1)

            # service removed
            zeroconf.handle_response(mock_incoming_msg(r.ServiceStateChange.Removed))
            dns_text = zeroconf.cache.get_by_details(service_name, r._TYPE_TXT, r._CLASS_IN)
            assert dns_text is None

        finally:
            zeroconf.close()


class Exceptions(unittest.TestCase):

    browser = None

    @classmethod
    def setUpClass(cls):
        cls.browser = Zeroconf(interfaces=['127.0.0.1'])

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        del cls.browser

    def test_bad_service_info_name(self):
        self.assertRaises(r.BadTypeInNameException, self.browser.get_service_info, "type", "type_not")

    def test_bad_service_names(self):
        bad_names_to_try = (
            '',
            'local',
            '_tcp.local.',
            '_udp.local.',
            '._udp.local.',
            '_@._tcp.local.',
            '_A@._tcp.local.',
            '_x--x._tcp.local.',
            '_-x._udp.local.',
            '_x-._tcp.local.',
            '_22._udp.local.',
            '_2-2._tcp.local.',
            '_1234567890-abcde._udp.local.',
            '\x00._x._udp.local.',
        )
        for name in bad_names_to_try:
            self.assertRaises(r.BadTypeInNameException, self.browser.get_service_info, name, 'x.' + name)

    def test_bad_local_names_for_get_service_info(self):
        bad_names_to_try = (
            'homekitdev._nothttp._tcp.local.',
            'homekitdev._http._udp.local.',
        )
        for name in bad_names_to_try:
            self.assertRaises(
                r.BadTypeInNameException, self.browser.get_service_info, '_http._tcp.local.', name
            )

    def test_good_instance_names(self):
        assert r.service_type_name('.._x._tcp.local.') == '_x._tcp.local.'
        assert r.service_type_name('x.sub._http._tcp.local.') == '_http._tcp.local.'
        assert (
            r.service_type_name('6d86f882b90facee9170ad3439d72a4d6ee9f511._zget._http._tcp.local.')
            == '_http._tcp.local.'
        )

    def test_good_instance_names_without_protocol(self):
        good_names_to_try = (
            "Rachio-C73233.local.",
            'YeelightColorBulb-3AFD.local.',
            'YeelightTunableBulb-7220.local.',
            "AlexanderHomeAssistant 74651D.local.",
            'iSmartGate-152.local.',
            'MyQ-FGA.local.',
            'lutron-02c4392a.local.',
            'WICED-hap-3E2734.local.',
            'MyHost.local.',
            'MyHost.sub.local.',
        )
        for name in good_names_to_try:
            assert r.service_type_name(name, strict=False) == 'local.'

        for name in good_names_to_try:
            # Raises without strict=False
            self.assertRaises(r.BadTypeInNameException, r.service_type_name, name)

    def test_bad_types(self):
        bad_names_to_try = (
            '._x._tcp.local.',
            'a' * 64 + '._sub._http._tcp.local.',
            'a' * 62 + u'â._sub._http._tcp.local.',
        )
        for name in bad_names_to_try:
            self.assertRaises(r.BadTypeInNameException, r.service_type_name, name)

    def test_bad_sub_types(self):
        bad_names_to_try = (
            '_sub._http._tcp.local.',
            '._sub._http._tcp.local.',
            '\x7f._sub._http._tcp.local.',
            '\x1f._sub._http._tcp.local.',
        )
        for name in bad_names_to_try:
            self.assertRaises(r.BadTypeInNameException, r.service_type_name, name)

    def test_good_service_names(self):
        good_names_to_try = (
            ('_x._tcp.local.', '_x._tcp.local.'),
            ('_x._udp.local.', '_x._udp.local.'),
            ('_12345-67890-abc._udp.local.', '_12345-67890-abc._udp.local.'),
            ('x._sub._http._tcp.local.', '_http._tcp.local.'),
            ('a' * 63 + '._sub._http._tcp.local.', '_http._tcp.local.'),
            ('a' * 61 + u'â._sub._http._tcp.local.', '_http._tcp.local.'),
        )

        for name, result in good_names_to_try:
            assert r.service_type_name(name) == result

        assert r.service_type_name('_one_two._tcp.local.', strict=False) == '_one_two._tcp.local.'

    def test_invalid_addresses(self):
        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)

        bad = ('127.0.0.1', '::1', 42)
        for addr in bad:
            six.assertRaisesRegex(
                self,
                TypeError,
                'Addresses must be bytes',
                ServiceInfo,
                type_,
                registration_name,
                port=80,
                addresses=[addr],
            )


class TestDnsIncoming(unittest.TestCase):
    def test_incoming_exception_handling(self):
        generated = r.DNSOutgoing(0)
        packet = generated.packet()
        packet = packet[:8] + b'deadbeef' + packet[8:]
        parsed = r.DNSIncoming(packet)
        parsed = r.DNSIncoming(packet)
        assert parsed.valid is False

    def test_incoming_unknown_type(self):
        generated = r.DNSOutgoing(0)
        answer = r.DNSAddress('a', r._TYPE_SOA, r._CLASS_IN, 1, b'a')
        generated.add_additional_answer(answer)
        packet = generated.packet()
        parsed = r.DNSIncoming(packet)
        assert len(parsed.answers) == 0
        assert parsed.is_query() != parsed.is_response()

    def test_incoming_ipv6(self):
        addr = "2606:2800:220:1:248:1893:25c8:1946"  # example.com
        packed = socket.inet_pton(socket.AF_INET6, addr)
        generated = r.DNSOutgoing(0)
        answer = r.DNSAddress('domain', r._TYPE_AAAA, r._CLASS_IN | r._CLASS_UNIQUE, 1, packed)
        generated.add_additional_answer(answer)
        packet = generated.packet()
        parsed = r.DNSIncoming(packet)
        record = parsed.answers[0]
        assert isinstance(record, r.DNSAddress)
        assert record.address == packed


class TestRegistrar(unittest.TestCase):
    def test_ttl(self):

        # instantiate a zeroconf instance
        zc = Zeroconf(interfaces=['127.0.0.1'])

        # service definition
        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)

        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            type_,
            registration_name,
            80,
            0,
            0,
            desc,
            "ash-2.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
        )

        # we are going to monkey patch the zeroconf send to check packet sizes
        old_send = zc.send

        class TestCtx(object):
            def __init__(self):
                self.nbr_answers = 0
                self.nbr_additionals = 0
                self.nbr_authorities = 0
        testCtx = TestCtx()

        def get_ttl(record_type):
            if expected_ttl is not None:
                return expected_ttl
            elif record_type in [r._TYPE_A, r._TYPE_SRV]:
                return r._DNS_HOST_TTL
            else:
                return r._DNS_OTHER_TTL

        def send(out, addr=r._MDNS_ADDR, port=r._MDNS_PORT):
            """Sends an outgoing packet."""
            for answer, time_ in out.answers:
                testCtx.nbr_answers += 1
                assert answer.ttl == get_ttl(answer.type)
            for answer in out.additionals:
                testCtx.nbr_additionals += 1
                assert answer.ttl == get_ttl(answer.type)
            for answer in out.authorities:
                testCtx.nbr_authorities += 1
                assert answer.ttl == get_ttl(answer.type)
            old_send(out, addr=addr, port=port)

        # monkey patch the zeroconf send
        setattr(zc, "send", send)

        # register service with default TTL
        expected_ttl = None
        zc.register_service(info)
        assert testCtx.nbr_answers == 12 and testCtx.nbr_additionals == 0 and testCtx.nbr_authorities == 3
        testCtx.nbr_answers = testCtx.nbr_additionals = testCtx.nbr_authorities = 0

        # query
        query = r.DNSOutgoing(r._FLAGS_QR_QUERY | r._FLAGS_AA)
        query.add_question(r.DNSQuestion(info.type, r._TYPE_PTR, r._CLASS_IN))
        query.add_question(r.DNSQuestion(info.name, r._TYPE_SRV, r._CLASS_IN))
        query.add_question(r.DNSQuestion(info.name, r._TYPE_TXT, r._CLASS_IN))
        query.add_question(r.DNSQuestion(info.server, r._TYPE_A, r._CLASS_IN))
        zc.handle_query(r.DNSIncoming(query.packet()), r._MDNS_ADDR, r._MDNS_PORT)
        assert testCtx.nbr_answers == 4 and testCtx.nbr_additionals == 4 and testCtx.nbr_authorities == 0
        testCtx.nbr_answers = testCtx.nbr_additionals = testCtx.nbr_authorities = 0

        # unregister
        expected_ttl = 0
        zc.unregister_service(info)
        assert testCtx.nbr_answers == 12 and testCtx.nbr_additionals == 0 and testCtx.nbr_authorities == 0
        testCtx.nbr_answers = testCtx.nbr_additionals = testCtx.nbr_authorities = 0

        # register service with custom TTL
        expected_ttl = r._DNS_HOST_TTL * 2
        assert expected_ttl != r._DNS_HOST_TTL
        zc.register_service(info, ttl=expected_ttl)
        assert testCtx.nbr_answers == 12 and testCtx.nbr_additionals == 0 and testCtx.nbr_authorities == 3
        testCtx.nbr_answers = testCtx.nbr_additionals = testCtx.nbr_authorities = 0

        # query
        query = r.DNSOutgoing(r._FLAGS_QR_QUERY | r._FLAGS_AA)
        query.add_question(r.DNSQuestion(info.type, r._TYPE_PTR, r._CLASS_IN))
        query.add_question(r.DNSQuestion(info.name, r._TYPE_SRV, r._CLASS_IN))
        query.add_question(r.DNSQuestion(info.name, r._TYPE_TXT, r._CLASS_IN))
        query.add_question(r.DNSQuestion(info.server, r._TYPE_A, r._CLASS_IN))
        zc.handle_query(r.DNSIncoming(query.packet()), r._MDNS_ADDR, r._MDNS_PORT)
        assert testCtx.nbr_answers == 4 and testCtx.nbr_additionals == 4 and testCtx.nbr_authorities == 0
        testCtx.nbr_answers = testCtx.nbr_additionals = testCtx.nbr_authorities = 0

        # unregister
        expected_ttl = 0
        zc.unregister_service(info)
        assert testCtx.nbr_answers == 12 and testCtx.nbr_additionals == 0 and testCtx.nbr_authorities == 0
        testCtx.nbr_answers = testCtx.nbr_additionals = testCtx.nbr_authorities = 0

        # close
        zc.close()

class TestServiceRegistry(unittest.TestCase):
    def test_only_register_once(self):
        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)

        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[socket.inet_aton("10.0.1.2")]
        )

        registry = r.ServiceRegistry()
        registry.add(info)
        self.assertRaises(r.ServiceNameAlreadyRegistered, registry.add, info)
        registry.remove(info)
        registry.add(info)

    def test_lookups(self):
        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)

        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[socket.inet_aton("10.0.1.2")]
        )

        registry = r.ServiceRegistry()
        registry.add(info)

        assert registry.get_service_infos() == [info]
        assert registry.get_info_name(registration_name) == info
        assert registry.get_infos_type(type_) == [info]
        assert registry.get_infos_server("ash-2.local.") == [info]
        assert registry.get_types() == [type_]


class TestDNSCache(unittest.TestCase):
    def test_order(self):
        record1 = r.DNSAddress('a', r._TYPE_SOA, r._CLASS_IN, 1, b'a')
        record2 = r.DNSAddress('a', r._TYPE_SOA, r._CLASS_IN, 1, b'b')
        cache = r.DNSCache()
        cache.add(record1)
        cache.add(record2)
        entry = r.DNSEntry('a', r._TYPE_SOA, r._CLASS_IN)
        cached_record = cache.get(entry)
        assert cached_record == record2

    def test_cache_empty_does_not_leak_memory_by_leaving_empty_list(self):
        record1 = r.DNSAddress('a', r._TYPE_SOA, r._CLASS_IN, 1, b'a')
        record2 = r.DNSAddress('a', r._TYPE_SOA, r._CLASS_IN, 1, b'b')
        cache = r.DNSCache()
        cache.add(record1)
        cache.add(record2)
        assert 'a' in cache.cache
        cache.remove(record1)
        cache.remove(record2)
        assert 'a' not in cache.cache

    def test_cache_empty_multiple_calls_does_not_throw(self):
        record1 = r.DNSAddress('a', r._TYPE_SOA, r._CLASS_IN, 1, b'a')
        record2 = r.DNSAddress('a', r._TYPE_SOA, r._CLASS_IN, 1, b'b')
        cache = r.DNSCache()
        cache.add(record1)
        cache.add(record2)
        assert 'a' in cache.cache
        cache.remove(record1)
        cache.remove(record2)
        # Ensure multiple removes does not throw
        cache.remove(record1)
        cache.remove(record2)
        assert 'a' not in cache.cache


class TestReaper(unittest.TestCase):
    def test_reaper(self):
        zeroconf = Zeroconf(interfaces=['127.0.0.1'])
        original_entries = zeroconf.cache.entries()
        record_with_10s_ttl = r.DNSAddress('a', r._TYPE_SOA, r._CLASS_IN, 10, b'a')
        record_with_1s_ttl = r.DNSAddress('a', r._TYPE_SOA, r._CLASS_IN, 1, b'b')
        zeroconf.cache.add(record_with_10s_ttl)
        zeroconf.cache.add(record_with_1s_ttl)
        entries_with_cache = zeroconf.cache.entries()
        time.sleep(1.05)
        zeroconf.notify_reaper()
        time.sleep(0.05)
        entries = zeroconf.cache.entries()

        try:
            iterable_entries = list(zeroconf.cache.iterable_entries())
        finally:
            zeroconf.close()

        assert entries != original_entries
        assert entries_with_cache != original_entries
        assert record_with_10s_ttl in entries
        assert record_with_1s_ttl not in entries
        assert record_with_10s_ttl in iterable_entries
        assert record_with_1s_ttl not in iterable_entries

    def test_reaper_with_dict_change_during_iteration(self):
        zeroconf = Zeroconf(interfaces=['127.0.0.1'])
        original_entries = zeroconf.cache.entries()
        record_with_10s_ttl = r.DNSAddress('a', r._TYPE_SOA, r._CLASS_IN, 10, b'a')
        record_with_1s_ttl = r.DNSAddress('a', r._TYPE_SOA, r._CLASS_IN, 1, b'b')
        zeroconf.cache.add(record_with_10s_ttl)
        zeroconf.cache.add(record_with_1s_ttl)
        entries_with_cache = zeroconf.cache.entries()
        with mock.patch("zeroconf.DNSCache.iterable_entries", side_effect=RuntimeError):
            time.sleep(1.05)
            zeroconf.notify_reaper()
            time.sleep(0.05)

        entries = zeroconf.cache.entries()
        zeroconf.close()

        assert entries != original_entries
        assert entries_with_cache != original_entries
        assert record_with_10s_ttl in entries
        assert record_with_1s_ttl not in entries


class ServiceTypesQuery(unittest.TestCase):
    def test_integration_with_listener(self):

        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)

        zeroconf_registrar = Zeroconf(interfaces=['127.0.0.1'])
        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            type_,
            registration_name,
            80,
            0,
            0,
            desc,
            "ash-2.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
        )
        zeroconf_registrar.register_service(info)

        try:
            service_types = ZeroconfServiceTypes.find(interfaces=['127.0.0.1'], timeout=0.5)
            assert type_ in service_types
            service_types = ZeroconfServiceTypes.find(zc=zeroconf_registrar, timeout=0.5)
            assert type_ in service_types

        finally:
            zeroconf_registrar.close()

    @unittest.skipIf(not socket.has_ipv6, 'Requires IPv6')
    @unittest.skipIf(os.environ.get('SKIP_IPV6'), 'IPv6 tests disabled')
    def test_integration_with_listener_v6_records(self):

        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)
        addr = "2606:2800:220:1:248:1893:25c8:1946"  # example.com

        zeroconf_registrar = Zeroconf(interfaces=['127.0.0.1'])
        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            type_,
            registration_name,
            80,
            0,
            0,
            desc,
            "ash-2.local.",
            addresses=[socket.inet_pton(socket.AF_INET6, addr)],
        )
        zeroconf_registrar.register_service(info)

        try:
            service_types = ZeroconfServiceTypes.find(interfaces=['127.0.0.1'], timeout=0.5)
            assert type_ in service_types
            service_types = ZeroconfServiceTypes.find(zc=zeroconf_registrar, timeout=0.5)
            assert type_ in service_types

        finally:
            zeroconf_registrar.close()

    @unittest.skipIf(not socket.has_ipv6, 'Requires IPv6')
    @unittest.skipIf(os.environ.get('SKIP_IPV6'), 'IPv6 tests disabled')
    def test_integration_with_listener_ipv6(self):

        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)

        zeroconf_registrar = Zeroconf(ip_version=r.IPVersion.V6Only)
        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            type_,
            registration_name,
            80,
            0,
            0,
            desc,
            "ash-2.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
        )
        zeroconf_registrar.register_service(info)

        try:
            service_types = ZeroconfServiceTypes.find(ip_version=r.IPVersion.V6Only, timeout=0.5)
            assert type_ in service_types
            service_types = ZeroconfServiceTypes.find(zc=zeroconf_registrar, timeout=0.5)
            assert type_ in service_types

        finally:
            zeroconf_registrar.close()

    def test_integration_with_subtype_and_listener(self):
        subtype_ = "_subtype._sub"
        type_ = "_type._tcp.local."
        name = "xxxyyy"
        # Note: discovery returns only DNS-SD type not subtype
        discovery_type = "%s.%s" % (subtype_, type_)
        registration_name = "%s.%s" % (name, type_)

        zeroconf_registrar = Zeroconf(interfaces=['127.0.0.1'])
        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            discovery_type,
            registration_name,
            80,
            0,
            0,
            desc,
            "ash-2.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
        )
        zeroconf_registrar.register_service(info)

        try:
            service_types = ZeroconfServiceTypes.find(interfaces=['127.0.0.1'], timeout=0.5)
            assert discovery_type in service_types
            service_types = ZeroconfServiceTypes.find(zc=zeroconf_registrar, timeout=0.5)
            assert discovery_type in service_types

        finally:
            zeroconf_registrar.close()


class ListenerTest(unittest.TestCase):
    @pytest.mark.skipif(platform.python_implementation() == 'PyPy', reason="Flaky on PyPy")
    def test_integration_with_listener_class(self):

        service_added = Event()
        service_removed = Event()
        service_updated = Event()
        service_updated2 = Event()

        subtype_name = "My special Subtype"
        type_ = "_http._tcp.local."
        subtype = subtype_name + "._sub." + type_
        # Should use the "u" prefix so it works in both python2 and python3
        name = u"xxxyyyæøå"
        registration_name = "%s.%s" % (name, subtype)

        class MyListener(r.ServiceListener):
            def add_service(self, zeroconf, type, name):
                zeroconf.get_service_info(type, name)
                service_added.set()

            def remove_service(self, zeroconf, type, name):
                service_removed.set()

            def update_service(self, zeroconf, type, name):
                service_updated2.set()

        class MySubListener(r.ServiceListener):
            def add_service(self, zeroconf, type, name):
                pass

            def remove_service(self, zeroconf, type, name):
                pass

            def update_service(self, zeroconf, type, name):
                service_updated.set()

        listener = MyListener()
        zeroconf_browser = Zeroconf(interfaces=['127.0.0.1'])
        zeroconf_browser.add_service_listener(subtype, listener)

        properties = dict(
            prop_none=None,
            prop_string=b'a_prop',
            prop_float=1.0,
            prop_blank=b'a blanked string',
            prop_true=1,
            prop_false=0,
        )

        zeroconf_registrar = Zeroconf(interfaces=['127.0.0.1'])
        desc = {'path': '/~paulsm/'}
        desc.update(properties)
        addresses = [socket.inet_aton("10.0.1.2")]
        if socket.has_ipv6 and not os.environ.get('SKIP_IPV6'):
            addresses.append(socket.inet_pton(socket.AF_INET6, "2001:db8::1"))
        info_service = ServiceInfo(
            subtype, registration_name, port=80, properties=desc, server="ash-2.local.", addresses=addresses
        )
        zeroconf_registrar.register_service(info_service)

        try:
            service_added.wait(1)
            assert service_added.is_set()

            # short pause to allow multicast timers to expire
            time.sleep(3)

            # clear the answer cache to force query
            for record in zeroconf_browser.cache.entries():
                zeroconf_browser.cache.remove(record)

            # get service info without answer cache
            info = zeroconf_browser.get_service_info(type_, registration_name)
            assert info is not None
            assert info.properties[b'prop_none'] is None
            assert info.properties[b'prop_string'] == properties['prop_string']
            assert info.properties[b'prop_float'] == b'1.0'
            assert info.properties[b'prop_blank'] == properties['prop_blank']
            assert info.properties[b'prop_true'] == b'1'
            assert info.properties[b'prop_false'] == b'0'
            assert info.addresses == addresses[:1]  # no V6 by default
            assert info.addresses_by_version(r.IPVersion.All) == addresses

            info = zeroconf_browser.get_service_info(subtype, registration_name)
            assert info is not None
            assert info.properties[b'prop_none'] is None

            # test TXT record update
            sublistener = MySubListener()
            zeroconf_browser.add_service_listener(registration_name, sublistener)
            properties['prop_blank'] = b'an updated string'
            desc.update(properties)
            info_service = ServiceInfo(
                subtype,
                registration_name,
                80,
                0,
                0,
                desc,
                "ash-2.local.",
                addresses=[socket.inet_aton("10.0.1.2")],
            )
            zeroconf_registrar.update_service(info_service)
            service_updated.wait(1)
            assert service_updated.is_set()

            info = zeroconf_browser.get_service_info(type_, registration_name)
            assert info is not None
            assert info.properties[b'prop_blank'] == properties['prop_blank']

            zeroconf_registrar.unregister_service(info_service)
            service_removed.wait(1)
            assert service_removed.is_set()

        finally:
            zeroconf_registrar.close()
            zeroconf_browser.remove_service_listener(listener)
            zeroconf_browser.close()


class TestServiceBrowser(unittest.TestCase):
    def test_update_record(self):

        service_name = 'name._type._tcp.local.'
        service_type = '_type._tcp.local.'
        service_server = 'ash-1.local.'
        service_text = b'path=/~matt1/'
        service_address = '10.0.1.2'

        class TestCtx(object):
            def __init__(self):
                self.service_added_count = 0
                self.service_removed_count = 0
                self.service_updated_count = 0
        testCtx = TestCtx()

        service_add_event = Event()
        service_removed_event = Event()
        service_updated_event = Event()

        class MyServiceListener(r.ServiceListener):
            def add_service(self, zc, type_, name):
                testCtx.service_added_count += 1
                service_add_event.set()

            def remove_service(self, zc, type_, name):
                testCtx.service_removed_count += 1
                service_removed_event.set()

            def update_service(self, zc, type_, name):
                testCtx.service_updated_count += 1
                service_info = zc.get_service_info(type_, name)
                assert service_info.addresses[0] == socket.inet_aton(service_address)
                assert service_info.text == service_text
                assert service_info.server == service_server
                service_updated_event.set()

        def mock_incoming_msg(service_state_change):

            generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)

            if service_state_change == r.ServiceStateChange.Removed:
                ttl = 0
            else:
                ttl = 120

            generated.add_answer_at_time(
                r.DNSText(service_name, r._TYPE_TXT, r._CLASS_IN | r._CLASS_UNIQUE, ttl, service_text), 0
            )

            generated.add_answer_at_time(
                r.DNSService(
                    service_name, r._TYPE_SRV, r._CLASS_IN | r._CLASS_UNIQUE, ttl, 0, 0, 80, service_server
                ),
                0,
            )

            generated.add_answer_at_time(
                r.DNSAddress(
                    service_server,
                    r._TYPE_A,
                    r._CLASS_IN | r._CLASS_UNIQUE,
                    ttl,
                    socket.inet_aton(service_address),
                ),
                0,
            )

            generated.add_answer_at_time(
                r.DNSPointer(service_type, r._TYPE_PTR, r._CLASS_IN, ttl, service_name), 0
            )

            return r.DNSIncoming(generated.packet())

        zeroconf = r.Zeroconf(interfaces=['127.0.0.1'])
        service_browser = r.ServiceBrowser(zeroconf, service_type, listener=MyServiceListener())

        try:
            wait_time = 3

            # service added
            zeroconf.handle_response(mock_incoming_msg(r.ServiceStateChange.Added))
            service_add_event.wait(wait_time)
            assert testCtx.service_added_count == 1
            assert testCtx.service_updated_count == 0
            assert testCtx.service_removed_count == 0

            # service SRV updated
            service_updated_event.clear()
            service_server = 'ash-2.local.'
            zeroconf.handle_response(mock_incoming_msg(r.ServiceStateChange.Updated))
            service_updated_event.wait(wait_time)
            assert testCtx.service_added_count == 1
            assert testCtx.service_updated_count == 1
            assert testCtx.service_removed_count == 0

            # service TXT updated
            service_updated_event.clear()
            service_text = b'path=/~matt2/'
            zeroconf.handle_response(mock_incoming_msg(r.ServiceStateChange.Updated))
            service_updated_event.wait(wait_time)
            assert testCtx.service_added_count == 1
            assert testCtx.service_updated_count == 2
            assert testCtx.service_removed_count == 0

            # service A updated
            service_updated_event.clear()
            service_address = '10.0.1.3'
            zeroconf.handle_response(mock_incoming_msg(r.ServiceStateChange.Updated))
            service_updated_event.wait(wait_time)
            assert testCtx.service_added_count == 1
            assert testCtx.service_updated_count == 3
            assert testCtx.service_removed_count == 0

            # service all updated
            service_updated_event.clear()
            service_server = 'ash-3.local.'
            service_text = b'path=/~matt3/'
            service_address = '10.0.1.3'
            zeroconf.handle_response(mock_incoming_msg(r.ServiceStateChange.Updated))
            service_updated_event.wait(wait_time)
            assert testCtx.service_added_count == 1
            assert testCtx.service_updated_count == 4
            assert testCtx.service_removed_count == 0

            # service removed
            zeroconf.handle_response(mock_incoming_msg(r.ServiceStateChange.Removed))
            service_removed_event.wait(wait_time)
            assert testCtx.service_added_count == 1
            assert testCtx.service_updated_count == 4
            assert testCtx.service_removed_count == 1

        finally:
            assert len(zeroconf.listeners) == 1
            service_browser.cancel()
            assert len(zeroconf.listeners) == 0
            zeroconf.remove_all_service_listeners()
            zeroconf.close()


class TestServiceInfo(unittest.TestCase):
    def test_get_info_partial(self):

        zc = r.Zeroconf(interfaces=['127.0.0.1'])

        service_name = 'name._type._tcp.local.'
        service_type = '_type._tcp.local.'
        service_server = 'ash-1.local.'
        service_text = b'path=/~matt1/'
        service_address = '10.0.1.2'

        send_event = Event()
        service_info_event = Event()

        class TestCtx(object):
            def __init__(self):
                self.last_sent = None
                self.service_info = None
        testCtx = TestCtx()

        def send(out, addr=r._MDNS_ADDR, port=r._MDNS_PORT):
            """Sends an outgoing packet."""
            testCtx.last_sent = out
            send_event.set()

        # monkey patch the zeroconf send
        setattr(zc, "send", send)

        def mock_incoming_msg(records):

            generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)

            for record in records:
                generated.add_answer_at_time(record, 0)

            return r.DNSIncoming(generated.packet())

        def get_service_info_helper(zc, type, name):
            testCtx.service_info = zc.get_service_info(type, name)
            service_info_event.set()

        try:
            ttl = 120
            helper_thread = threading.Thread(
                target=get_service_info_helper, args=(zc, service_type, service_name)
            )
            helper_thread.start()
            wait_time = 1

            # Expext query for SRV, TXT, A, AAAA
            send_event.wait(wait_time)
            assert testCtx.last_sent is not None
            assert len(testCtx.last_sent.questions) == 4
            assert r.DNSQuestion(service_name, r._TYPE_SRV, r._CLASS_IN) in testCtx.last_sent.questions
            assert r.DNSQuestion(service_name, r._TYPE_TXT, r._CLASS_IN) in testCtx.last_sent.questions
            assert r.DNSQuestion(service_name, r._TYPE_A, r._CLASS_IN) in testCtx.last_sent.questions
            assert r.DNSQuestion(service_name, r._TYPE_AAAA, r._CLASS_IN) in testCtx.last_sent.questions
            assert testCtx.service_info is None

            # Expext query for SRV, A, AAAA
            testCtx.last_sent = None
            send_event.clear()
            zc.handle_response(
                mock_incoming_msg(
                    [r.DNSText(service_name, r._TYPE_TXT, r._CLASS_IN | r._CLASS_UNIQUE, ttl, service_text)]
                )
            )
            send_event.wait(wait_time)
            assert testCtx.last_sent is not None
            assert len(testCtx.last_sent.questions) == 3
            assert r.DNSQuestion(service_name, r._TYPE_SRV, r._CLASS_IN) in testCtx.last_sent.questions
            assert r.DNSQuestion(service_name, r._TYPE_A, r._CLASS_IN) in testCtx.last_sent.questions
            assert r.DNSQuestion(service_name, r._TYPE_AAAA, r._CLASS_IN) in testCtx.last_sent.questions
            assert testCtx.service_info is None

            # Expext query for A, AAAA
            testCtx.last_sent = None
            send_event.clear()
            zc.handle_response(
                mock_incoming_msg(
                    [
                        r.DNSService(
                            service_name,
                            r._TYPE_SRV,
                            r._CLASS_IN | r._CLASS_UNIQUE,
                            ttl,
                            0,
                            0,
                            80,
                            service_server,
                        )
                    ]
                )
            )
            send_event.wait(wait_time)
            assert testCtx.last_sent is not None
            assert len(testCtx.last_sent.questions) == 2
            assert r.DNSQuestion(service_server, r._TYPE_A, r._CLASS_IN) in testCtx.last_sent.questions
            assert r.DNSQuestion(service_server, r._TYPE_AAAA, r._CLASS_IN) in testCtx.last_sent.questions
            testCtx.last_sent = None
            assert testCtx.service_info is None

            # Expext no further queries
            testCtx.last_sent = None
            send_event.clear()
            zc.handle_response(
                mock_incoming_msg(
                    [
                        r.DNSAddress(
                            service_server,
                            r._TYPE_A,
                            r._CLASS_IN | r._CLASS_UNIQUE,
                            ttl,
                            socket.inet_pton(socket.AF_INET, service_address),
                        )
                    ]
                )
            )
            send_event.wait(wait_time)
            assert testCtx.last_sent is None
            assert testCtx.service_info is not None

        finally:
            helper_thread.join()
            zc.remove_all_service_listeners()
            zc.close()

    def test_get_info_single(self):

        zc = r.Zeroconf(interfaces=['127.0.0.1'])

        service_name = 'name._type._tcp.local.'
        service_type = '_type._tcp.local.'
        service_server = 'ash-1.local.'
        service_text = b'path=/~matt1/'
        service_address = '10.0.1.2'

        send_event = Event()
        service_info_event = Event()

        class TestCtx(object):
            def __init__(self):
                self.last_sent = None
                self.service_info = None
        testCtx = TestCtx()

        def send(out, addr=r._MDNS_ADDR, port=r._MDNS_PORT):
            """Sends an outgoing packet."""
            testCtx.last_sent = out
            send_event.set()

        # monkey patch the zeroconf send
        setattr(zc, "send", send)

        def mock_incoming_msg(records):

            generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)

            for record in records:
                generated.add_answer_at_time(record, 0)

            return r.DNSIncoming(generated.packet())

        def get_service_info_helper(zc, type, name):
            testCtx.service_info = zc.get_service_info(type, name)
            service_info_event.set()

        try:
            ttl = 120
            helper_thread = threading.Thread(
                target=get_service_info_helper, args=(zc, service_type, service_name)
            )
            helper_thread.start()
            wait_time = 1

            # Expext query for SRV, TXT, A, AAAA
            send_event.wait(wait_time)
            assert testCtx.last_sent is not None
            assert len(testCtx.last_sent.questions) == 4
            assert r.DNSQuestion(service_name, r._TYPE_SRV, r._CLASS_IN) in testCtx.last_sent.questions
            assert r.DNSQuestion(service_name, r._TYPE_TXT, r._CLASS_IN) in testCtx.last_sent.questions
            assert r.DNSQuestion(service_name, r._TYPE_A, r._CLASS_IN) in testCtx.last_sent.questions
            assert r.DNSQuestion(service_name, r._TYPE_AAAA, r._CLASS_IN) in testCtx.last_sent.questions
            assert testCtx.service_info is None

            # Expext no further queries
            testCtx.last_sent = None
            send_event.clear()
            zc.handle_response(
                mock_incoming_msg(
                    [
                        r.DNSText(
                            service_name, r._TYPE_TXT, r._CLASS_IN | r._CLASS_UNIQUE, ttl, service_text
                        ),
                        r.DNSService(
                            service_name,
                            r._TYPE_SRV,
                            r._CLASS_IN | r._CLASS_UNIQUE,
                            ttl,
                            0,
                            0,
                            80,
                            service_server,
                        ),
                        r.DNSAddress(
                            service_server,
                            r._TYPE_A,
                            r._CLASS_IN | r._CLASS_UNIQUE,
                            ttl,
                            socket.inet_pton(socket.AF_INET, service_address),
                        ),
                    ]
                )
            )
            send_event.wait(wait_time)
            assert testCtx.last_sent is None
            assert testCtx.service_info is not None

        finally:
            helper_thread.join()
            zc.remove_all_service_listeners()
            zc.close()


class TestServiceBrowserMultipleTypes(unittest.TestCase):
    def test_update_record(self):

        service_names = ['name2._type2._tcp.local.', 'name._type._tcp.local.', 'name._type._udp.local']
        service_types = ['_type2._tcp.local.', '_type._tcp.local.', '_type._udp.local.']

        class TestCtx(object):
            def __init__(self):
                self.service_added_count = 0
                self.service_removed_count = 0
                self.called_with_refresh_time_check = False
        testCtx = TestCtx()

        service_add_event = Event()
        service_removed_event = Event()

        class MyServiceListener(r.ServiceListener):
            def add_service(self, zc, type_, name):
                testCtx.service_added_count += 1
                if testCtx.service_added_count == 3:
                    service_add_event.set()

            def remove_service(self, zc, type_, name):
                testCtx.service_removed_count += 1
                if testCtx.service_removed_count == 3:
                    service_removed_event.set()

        def mock_incoming_msg(service_state_change, service_type, service_name, ttl):
            generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
            generated.add_answer_at_time(
                r.DNSPointer(service_type, r._TYPE_PTR, r._CLASS_IN, ttl, service_name), 0
            )
            return r.DNSIncoming(generated.packet())

        zeroconf = r.Zeroconf(interfaces=['127.0.0.1'])
        service_browser = r.ServiceBrowser(zeroconf, service_types, listener=MyServiceListener())

        try:
            wait_time = 3

            # all three services added
            zeroconf.handle_response(
                mock_incoming_msg(r.ServiceStateChange.Added, service_types[0], service_names[0], 120)
            )
            zeroconf.handle_response(
                mock_incoming_msg(r.ServiceStateChange.Added, service_types[1], service_names[1], 120)
            )
            zeroconf.handle_response(
                mock_incoming_msg(r.ServiceStateChange.Added, service_types[2], service_names[2], 120)
            )

            def _mock_get_expiration_time(self, percent):
                if percent == _EXPIRE_REFRESH_TIME_PERCENT:
                    testCtx.called_with_refresh_time_check = True
                    return 0
                return self.created + (percent * self.ttl * 10)

            # Set an expire time that will force a refresh
            with mock.patch("zeroconf.DNSRecord.get_expiration_time", new=_mock_get_expiration_time):
                zeroconf.handle_response(
                    mock_incoming_msg(r.ServiceStateChange.Added, service_types[2], service_names[2], 120)
                )
            service_add_event.wait(wait_time)
            assert testCtx.called_with_refresh_time_check is True
            assert testCtx.service_added_count == 3
            assert testCtx.service_removed_count == 0

            # all three services removed
            zeroconf.handle_response(
                mock_incoming_msg(r.ServiceStateChange.Removed, service_types[0], service_names[0], 0)
            )
            zeroconf.handle_response(
                mock_incoming_msg(r.ServiceStateChange.Removed, service_types[1], service_names[1], 0)
            )
            zeroconf.handle_response(
                mock_incoming_msg(r.ServiceStateChange.Removed, service_types[2], service_names[2], 0)
            )
            service_removed_event.wait(wait_time)
            assert testCtx.service_added_count == 3
            assert testCtx.service_removed_count == 3

        finally:
            assert len(zeroconf.listeners) == 1
            service_browser.cancel()
            assert len(zeroconf.listeners) == 0
            zeroconf.remove_all_service_listeners()
            zeroconf.close()


def test_backoff():
    got_query = Event()

    type_ = "_http._tcp.local."
    zeroconf_browser = Zeroconf(interfaces=['127.0.0.1'])

    # we are going to monkey patch the zeroconf send to check query transmission
    old_send = zeroconf_browser.send

    time_offset = 0.0
    start_time = time.time() * 1000
    initial_query_interval = r._BROWSER_TIME / 1000

    def current_time_millis():
        """Current system time in milliseconds"""
        return start_time + time_offset * 1000

    def send(out, addr=r._MDNS_ADDR, port=r._MDNS_PORT):
        """Sends an outgoing packet."""
        got_query.set()
        old_send(out, addr=addr, port=port)

    # monkey patch the zeroconf send
    setattr(zeroconf_browser, "send", send)

    # monkey patch the zeroconf current_time_millis
    r.current_time_millis = current_time_millis

    # monkey patch the backoff limit to prevent test running forever
    r._BROWSER_BACKOFF_LIMIT = 10  # seconds

    # dummy service callback
    def on_service_state_change(zeroconf, service_type, state_change, name):
        pass

    browser = ServiceBrowser(zeroconf_browser, type_, [on_service_state_change])

    try:
        # Test that queries are sent at increasing intervals
        sleep_count = 0
        next_query_interval = 0.0
        expected_query_time = 0.0
        while True:
            zeroconf_browser.notify_all()
            sleep_count += 1
            got_query.wait(0.1)
            if time_offset == expected_query_time:
                assert got_query.is_set()
                got_query.clear()
                if next_query_interval == r._BROWSER_BACKOFF_LIMIT:
                    # Only need to test up to the point where we've seen a query
                    # after the backoff limit has been hit
                    break
                elif next_query_interval == 0:
                    next_query_interval = initial_query_interval
                    expected_query_time = initial_query_interval
                else:
                    next_query_interval = min(2 * next_query_interval, r._BROWSER_BACKOFF_LIMIT)
                    expected_query_time += next_query_interval
            else:
                assert not got_query.is_set()
            time_offset += initial_query_interval

    finally:
        browser.cancel()
        zeroconf_browser.close()


def test_integration():
    service_added = Event()
    service_removed = Event()
    unexpected_ttl = Event()
    got_query = Event()

    type_ = "_http._tcp.local."
    registration_name = "xxxyyy.%s" % type_

    def on_service_state_change(zeroconf, service_type, state_change, name):
        if name == registration_name:
            if state_change is ServiceStateChange.Added:
                service_added.set()
            elif state_change is ServiceStateChange.Removed:
                service_removed.set()

    zeroconf_browser = Zeroconf(interfaces=['127.0.0.1'])

    # we are going to monkey patch the zeroconf send to check packet sizes
    old_send = zeroconf_browser.send

    time_offset = 0.0

    def current_time_millis():
        """Current system time in milliseconds"""
        return time.time() * 1000 + time_offset * 1000

    expected_ttl = r._DNS_HOST_TTL

    class TestCtx(object):
        def __init__(self):
            self.nbr_answers = 0
    testCtx = TestCtx()

    def send(out, addr=r._MDNS_ADDR, port=r._MDNS_PORT):
        """Sends an outgoing packet."""
        pout = r.DNSIncoming(out.packet())
        for answer in pout.answers:
            testCtx.nbr_answers += 1
            if not answer.ttl > expected_ttl / 2:
                unexpected_ttl.set()

        got_query.set()
        old_send(out, addr=addr, port=port)

    # monkey patch the zeroconf send
    setattr(zeroconf_browser, "send", send)

    # monkey patch the zeroconf current_time_millis
    r.current_time_millis = current_time_millis

    # monkey patch the backoff limit to ensure we always get one query every 1/4 of the DNS TTL
    r._BROWSER_BACKOFF_LIMIT = int(expected_ttl / 4)

    service_added = Event()
    service_removed = Event()

    browser = ServiceBrowser(zeroconf_browser, type_, [on_service_state_change])

    zeroconf_registrar = Zeroconf(interfaces=['127.0.0.1'])
    desc = {'path': '/~paulsm/'}
    info = ServiceInfo(
        type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[socket.inet_aton("10.0.1.2")]
    )
    zeroconf_registrar.register_service(info)

    try:
        service_added.wait(1)
        assert service_added.is_set()

        # Test that we receive queries containing answers only if the remaining TTL
        # is greater than half the original TTL
        sleep_count = 0
        test_iterations = 50
        while testCtx.nbr_answers < test_iterations:
            # Increase simulated time shift by 1/4 of the TTL in seconds
            time_offset += expected_ttl / 4
            zeroconf_browser.notify_all()
            sleep_count += 1
            got_query.wait(0.1)
            got_query.clear()
            # Prevent the test running indefinitely in an error condition
            assert sleep_count < test_iterations * 4
        assert not unexpected_ttl.is_set()

        # Don't remove service, allow close() to cleanup

    finally:
        zeroconf_registrar.close()
        service_removed.wait(1)
        assert service_removed.is_set()
        browser.cancel()
        zeroconf_browser.close()


def test_multiple_addresses():
    type_ = "_http._tcp.local."
    registration_name = "xxxyyy.%s" % type_
    desc = {'path': '/~paulsm/'}
    address_parsed = "10.0.1.2"
    address = socket.inet_aton(address_parsed)

    # New kwarg way
    info = ServiceInfo(type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[address, address])

    assert info.addresses == [address, address]

    info = ServiceInfo(
        type_,
        registration_name,
        80,
        0,
        0,
        desc,
        "ash-2.local.",
        parsed_addresses=[address_parsed, address_parsed],
    )
    assert info.addresses == [address, address]

    if socket.has_ipv6 and not os.environ.get('SKIP_IPV6'):
        address_v6_parsed = "2001:db8::1"
        address_v6 = socket.inet_pton(socket.AF_INET6, address_v6_parsed)
        infos = [
            ServiceInfo(
                type_,
                registration_name,
                80,
                0,
                0,
                desc,
                "ash-2.local.",
                addresses=[address, address_v6],
            ),
            ServiceInfo(
                type_,
                registration_name,
                80,
                0,
                0,
                desc,
                "ash-2.local.",
                parsed_addresses=[address_parsed, address_v6_parsed],
            ),
        ]
        for info in infos:
            assert info.addresses == [address]
            assert info.addresses_by_version(r.IPVersion.All) == [address, address_v6]
            assert info.addresses_by_version(r.IPVersion.V4Only) == [address]
            assert info.addresses_by_version(r.IPVersion.V6Only) == [address_v6]
            assert info.parsed_addresses() == [address_parsed, address_v6_parsed]
            assert info.parsed_addresses(r.IPVersion.V4Only) == [address_parsed]
            assert info.parsed_addresses(r.IPVersion.V6Only) == [address_v6_parsed]


def test_ptr_optimization():

    print("XXX")

    # instantiate a zeroconf instance
    zc = Zeroconf(interfaces=['127.0.0.1'])

    # service definition
    type_ = "_test-srvc-type._tcp.local."
    name = "xxxyyy"
    registration_name = "%s.%s" % (name, type_)

    desc = {'path': '/~paulsm/'}
    info = ServiceInfo(
        type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[socket.inet_aton("10.0.1.2")]
    )

    # we are going to monkey patch the zeroconf send to check packet sizes
    old_send = zc.send

    class TestCtx(object):
        def __init__(self):
            self.nbr_answers = 0
            self.nbr_additionals = 0
            self.nbr_authorities = 0
            self.has_srv = False
            self.has_txt = False
            self.has_a = False
    testCtx = TestCtx()

    def send(out, addr=r._MDNS_ADDR, port=r._MDNS_PORT):
        """Sends an outgoing packet."""
        testCtx.nbr_answers += len(out.answers)
        testCtx.nbr_authorities += len(out.authorities)
        for answer in out.additionals:
            testCtx.nbr_additionals += 1
            if answer.type == r._TYPE_SRV:
                testCtx.has_srv = True
            elif answer.type == r._TYPE_TXT:
                testCtx.has_txt = True
            elif answer.type == r._TYPE_A:
                testCtx.has_a = True

        old_send(out, addr=addr, port=port)

    # monkey patch the zeroconf send
    setattr(zc, "send", send)

    # register
    zc.register_service(info)
    testCtx.nbr_answers = testCtx.nbr_additionals = testCtx.nbr_authorities = 0

    # query
    query = r.DNSOutgoing(r._FLAGS_QR_QUERY | r._FLAGS_AA)
    query.add_question(r.DNSQuestion(info.type, r._TYPE_PTR, r._CLASS_IN))
    zc.handle_query(r.DNSIncoming(query.packet()), r._MDNS_ADDR, r._MDNS_PORT)
    assert testCtx.nbr_answers == 1 and testCtx.nbr_additionals == 3 and testCtx.nbr_authorities == 0
    assert testCtx.has_srv and testCtx.has_txt and testCtx.has_a

    # unregister
    zc.unregister_service(info)


def test_dns_compression_rollback_for_corruption():
    """Verify rolling back does not lead to dns compression corruption."""
    out = r.DNSOutgoing(r._FLAGS_QR_RESPONSE | r._FLAGS_AA)
    address = socket.inet_pton(socket.AF_INET, "192.168.208.5")

    additionals = [
        {
            "name": "HASS Bridge ZJWH FF5137._hap._tcp.local.",
            "address": address,
            "port": 51832,
            "text": b"\x13md=HASS Bridge"
            b" ZJWH\x06pv=1.0\x14id=01:6B:30:FF:51:37\x05c#=12\x04s#=1\x04ff=0\x04"
            b"ci=2\x04sf=0\x0bsh=L0m/aQ==",
        },
        {
            "name": "HASS Bridge 3K9A C2582A._hap._tcp.local.",
            "address": address,
            "port": 51834,
            "text": b"\x13md=HASS Bridge"
            b" 3K9A\x06pv=1.0\x14id=E2:AA:5B:C2:58:2A\x05c#=12\x04s#=1\x04ff=0\x04"
            b"ci=2\x04sf=0\x0bsh=b2CnzQ==",
        },
        {
            "name": "Master Bed TV CEDB27._hap._tcp.local.",
            "address": address,
            "port": 51830,
            "text": b"\x10md=Master Bed"
            b" TV\x06pv=1.0\x14id=9E:B7:44:CE:DB:27\x05c#=18\x04s#=1\x04ff=0\x05"
            b"ci=31\x04sf=0\x0bsh=CVj1kw==",
        },
        {
            "name": "Living Room TV 921B77._hap._tcp.local.",
            "address": address,
            "port": 51833,
            "text": b"\x11md=Living Room"
            b" TV\x06pv=1.0\x14id=11:61:E7:92:1B:77\x05c#=17\x04s#=1\x04ff=0\x05"
            b"ci=31\x04sf=0\x0bsh=qU77SQ==",
        },
        {
            "name": "HASS Bridge ZC8X FF413D._hap._tcp.local.",
            "address": address,
            "port": 51829,
            "text": b"\x13md=HASS Bridge"
            b" ZC8X\x06pv=1.0\x14id=96:14:45:FF:41:3D\x05c#=12\x04s#=1\x04ff=0\x04"
            b"ci=2\x04sf=0\x0bsh=b0QZlg==",
        },
        {
            "name": "HASS Bridge WLTF 4BE61F._hap._tcp.local.",
            "address": address,
            "port": 51837,
            "text": b"\x13md=HASS Bridge"
            b" WLTF\x06pv=1.0\x14id=E0:E7:98:4B:E6:1F\x04c#=2\x04s#=1\x04ff=0\x04"
            b"ci=2\x04sf=0\x0bsh=ahAISA==",
        },
        {
            "name": "FrontdoorCamera 8941D1._hap._tcp.local.",
            "address": address,
            "port": 54898,
            "text": b"\x12md=FrontdoorCamera\x06pv=1.0\x14id=9F:B7:DC:89:41:D1\x04c#=2\x04"
            b"s#=1\x04ff=0\x04ci=2\x04sf=0\x0bsh=0+MXmA==",
        },
        {
            "name": "HASS Bridge W9DN 5B5CC5._hap._tcp.local.",
            "address": address,
            "port": 51836,
            "text": b"\x13md=HASS Bridge"
            b" W9DN\x06pv=1.0\x14id=11:8E:DB:5B:5C:C5\x05c#=12\x04s#=1\x04ff=0\x04"
            b"ci=2\x04sf=0\x0bsh=6fLM5A==",
        },
        {
            "name": "HASS Bridge Y9OO EFF0A7._hap._tcp.local.",
            "address": address,
            "port": 51838,
            "text": b"\x13md=HASS Bridge"
            b" Y9OO\x06pv=1.0\x14id=D3:FE:98:EF:F0:A7\x04c#=2\x04s#=1\x04ff=0\x04"
            b"ci=2\x04sf=0\x0bsh=u3bdfw==",
        },
        {
            "name": "Snooze Room TV 6B89B0._hap._tcp.local.",
            "address": address,
            "port": 51835,
            "text": b"\x11md=Snooze Room"
            b" TV\x06pv=1.0\x14id=5F:D5:70:6B:89:B0\x05c#=17\x04s#=1\x04ff=0\x05"
            b"ci=31\x04sf=0\x0bsh=xNTqsg==",
        },
        {
            "name": "AlexanderHomeAssistant 74651D._hap._tcp.local.",
            "address": address,
            "port": 54811,
            "text": b"\x19md=AlexanderHomeAssistant\x06pv=1.0\x14id=59:8A:0B:74:65:1D\x05"
            b"c#=14\x04s#=1\x04ff=0\x04ci=2\x04sf=0\x0bsh=ccZLPA==",
        },
        {
            "name": "HASS Bridge OS95 39C053._hap._tcp.local.",
            "address": address,
            "port": 51831,
            "text": b"\x13md=HASS Bridge"
            b" OS95\x06pv=1.0\x14id=7E:8C:E6:39:C0:53\x05c#=12\x04s#=1\x04ff=0\x04ci=2"
            b"\x04sf=0\x0bsh=Xfe5LQ==",
        },
    ]

    out.add_answer_at_time(
        DNSText(
            "HASS Bridge W9DN 5B5CC5._hap._tcp.local.",
            r._TYPE_TXT,
            r._CLASS_IN | r._CLASS_UNIQUE,
            r._DNS_OTHER_TTL,
            b'\x13md=HASS Bridge W9DN\x06pv=1.0\x14id=11:8E:DB:5B:5C:C5\x05c#=12\x04s#=1'
            b'\x04ff=0\x04ci=2\x04sf=0\x0bsh=6fLM5A==',
        ),
        0,
    )

    for record in additionals:
        out.add_additional_answer(
            r.DNSService(
                record["name"],  # type: ignore
                r._TYPE_SRV,
                r._CLASS_IN | r._CLASS_UNIQUE,
                r._DNS_HOST_TTL,
                0,
                0,
                record["port"],  # type: ignore
                record["name"],  # type: ignore
            )
        )
        out.add_additional_answer(
            r.DNSText(
                record["name"],  # type: ignore
                r._TYPE_TXT,
                r._CLASS_IN | r._CLASS_UNIQUE,
                r._DNS_OTHER_TTL,
                record["text"],  # type: ignore
            )
        )
        out.add_additional_answer(
            r.DNSAddress(
                record["name"],  # type: ignore
                r._TYPE_A,
                r._CLASS_IN | r._CLASS_UNIQUE,
                r._DNS_HOST_TTL,
                record["address"],  # type: ignore
            )
        )

    for packet in out.packets():
        # Verify we can process the packets we created to
        # ensure there is no corruption with the dns compression
        incoming = r.DNSIncoming(packet)
        assert incoming.valid is True
