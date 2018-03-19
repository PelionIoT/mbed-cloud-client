#!/usr/bin/env python
import argparse
import logging
import string
import subprocess
import sys
import time
import xml.etree.cElementTree as ElementTree
from io import BytesIO
from threading import Thread

logger = logging.getLogger('ta-junit-wrapper')


class TeeBytesIO(BytesIO):
    """duplicate each write command to an additional file object"""
    def __init__(self, tee_fh):
        self.tee_fh = tee_fh
        super(TeeBytesIO, self).__init__()

    def write(self, s):
        self.tee_fh.write(s)
        BytesIO.write(self, s)


def get_parser():
    parser = argparse.ArgumentParser(description='JUNIT wrapper')

    parser.add_argument(
        '-o',
        '--output-file',
        metavar='FILE',
        type=argparse.FileType('w'),
        help='output JUNIT XML file name',
        required=True
    )

    parser.add_argument(
        '-s',
        '--test-suite',
        metavar='NAME',
        help='test suite name',
        required=True
    )

    parser.add_argument(
        '-t',
        '--test-case',
        metavar='NAME',
        help='test case name',
        required=True
    )

    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='verbose - duplicate command output to STDOUT'
    )

    parser.add_argument(
        '--validate',
        action='store_true',
        help='validate generated XML against Jenkins XSD. Requires "requests" and "lxml" libraries'
    )

    parser.add_argument(
        '--command',
        nargs=argparse.REMAINDER,
        help='command to be executed'
    )
    return parser


def get_file_copy_worker(infile, outfile):
    def do_work(_infile, _outfile):
        for line in iter(_infile.readline, ''):
            _outfile.write(line)
        _infile.close()
    thread = Thread(target=do_work, args=(infile, outfile))
    thread.daemon = True
    thread.start()
    return thread


def generate_junit_xml(test_suite, test_case, out_fh, stdout, stderr, return_code, duration_in_sec, command):
    test_suite_root_element = ElementTree.Element(
        'testsuite',
        tests='1',
        name=test_suite.replace(' ', '_'),
        failures=str(1 if return_code != 0 else 0),
        time=str(duration_in_sec)
    )
    test_case_element = ElementTree.SubElement(
        test_suite_root_element,
        'testcase',
        time=str(duration_in_sec),
        name=test_case.replace(' ', '_')
    )
    ElementTree.SubElement(test_case_element, 'system-out').text = filter(
        lambda x: x in string.printable, stdout.getvalue()
    )
    ElementTree.SubElement(test_case_element, 'system-err').text = filter(
        lambda x: x in string.printable, stderr.getvalue()
    )

    if return_code != 0:
        failure_msg = 'Command "{cmd}" returned {ret}'.format(cmd=command, ret=return_code)
        ElementTree.SubElement(
            test_case_element,
            'failure',
            type='Non-Zero return code',
            message=failure_msg)

    ElementTree.ElementTree(test_suite_root_element).write(out_fh)


def main():
    parser = get_parser()
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        stream=sys.stdout
    )

    stdout = TeeBytesIO(sys.stdout) if args.verbose else BytesIO()
    stderr = TeeBytesIO(stdout)
    logger.debug('Executing + ' + ' '.join(args.command))
    start_time = time.time()
    process = subprocess.Popen(args.command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    threads = [
        get_file_copy_worker(process.stdout, stdout),
        get_file_copy_worker(process.stderr, stderr)
    ]
    for t in threads:  # wait for IO completion
        t.join()
    return_code = process.wait()
    logger.debug('Wrapped process return code ' + str(return_code))
    duration_in_sec = time.time() - start_time

    with args.output_file as fh:  # insure file object is closed - since it will be read in do_validate()
        generate_junit_xml(
            args.test_suite,
            args.test_case,
            fh,
            stdout,
            stderr,
            return_code,
            duration_in_sec,
            args.command
        )
    logger.debug('Generated JUNIT report file ' + args.output_file.name)

    if args.validate:
        do_validate(args.output_file.name)

    raise SystemExit(return_code)

if __name__ == '__main__':
    main()
