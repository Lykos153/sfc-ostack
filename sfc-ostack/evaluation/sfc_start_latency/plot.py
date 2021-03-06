#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8

"""
About: Plot results of SFC start and gap latency tests

       1. SFC start time: Time for creation of all SFC resources, which contains
       network ports, SF server instance, port chain and time for waiting all SF
       programs to be ready.

       2. SFC gap time: The time between last 'old' packet and first 'new'
       chain-processed packet.

Email: xianglinks@gmail.com
"""

import os
import sys
sys.path.append('../scripts/')
import tex

import ipdb
import numpy as np

import matplotlib as mpl
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from matplotlib.pyplot import cm

# Shared font config
font_size = 8
font_name = 'monospace'
mpl.rc('font', family=font_name)

# Maximal number of SF instances in the chain
MAX_CHN_NUM = 8
TEST_ROUND = 30

x = np.arange(1, MAX_CHN_NUM + 1, 1, dtype='int32')
width = 0.5

# 99% for two sided, student distribution
T_FACTOR = {
    30: 2.750,
    40: 2.704,
    50: 2.678
}

T_FACTOR_N = {
    '99-10': 3.169,
    '99.9-10': 4.587,
    '99-inf': 2.576,
    '99-15': 2.947,
    '99.9-15': 4.073
}

cmap = cm.get_cmap('tab10')
# cmap = plt.get_cmap('hsv')


def save_fig(fig, path):
    """Save fig to path"""
    fig.savefig(path + '.pdf', pad_inches=0,
                bbox_inches='tight', dpi=400, format='pdf')


def plot_single_node():
    """Plot results on single node"""

    base_path = './test_result/single_node/'

    fig_s, ax_arr = plt.subplots(2, sharex=True)

    ax_arr[0].set_title("SFC start time", fontsize=font_size +
                        1, fontname=font_name)

    ax_arr[1].set_title("SFC gap time", fontsize=font_size +
                        1, fontname=font_name)

    total_srv_chn_time = list()
    total_port_chn_time = list()
    total_gap_time = list()

    for srv_num in range(1, MAX_CHN_NUM + 1):
        ins_ts_len = 4 + 2 * srv_num
        ctl_csv = os.path.join(base_path, 'sfc-ts-ctl-%d.csv' % srv_num)
        ctl_arr = np.genfromtxt(ctl_csv, delimiter=',')
        ctl_arr = ctl_arr[:][:TEST_ROUND]

        srv_chn_time_arr = np.subtract(ctl_arr[:, [1]], ctl_arr[:, [0]])
        port_chn_time_arr = np.subtract(ctl_arr[:, [3]], ctl_arr[:, [2]])

        total_srv_chn_time.append(
            (
                np.average(srv_chn_time_arr),
                (T_FACTOR[TEST_ROUND] * np.std(srv_chn_time_arr)) /
                np.sqrt(TEST_ROUND - 1)
            )
        )

        total_port_chn_time.append(
            (
                np.average(port_chn_time_arr),
                (T_FACTOR[TEST_ROUND] * np.std(port_chn_time_arr)) /
                np.sqrt(TEST_ROUND - 1)
            )
        )

        ins_csv = os.path.join(base_path, 'sfc-ts-ins-1-%d.csv' % srv_num)
        ins_arr = np.genfromtxt(ins_csv, delimiter=',')
        ins_arr = ins_arr[:][:TEST_ROUND]
        gap_time_arr = np.subtract(ins_arr[:, [-2]], ins_arr[:, [-1]])

        total_gap_time.append(
            (
                np.average(gap_time_arr),
                (T_FACTOR[TEST_ROUND] * np.std(gap_time_arr)) /
                np.sqrt(TEST_ROUND - 1)
            )
        )

    # Plot server chain start time
    ax_arr[0].bar(
        x + width / 2.0, [y[0] for y in total_srv_chn_time], width, alpha=0.6,
        yerr=[y[1] for y in total_srv_chn_time], color='blue', edgecolor='blue',
        error_kw=dict(elinewidth=1, ecolor='black'),
        label='Server Chain'
    )

    ax_arr[0].bar(
        x + width / 2.0, [y[0] for y in total_port_chn_time], width, alpha=0.6,
        yerr=[y[1] for y in total_port_chn_time], color='green', edgecolor='green',
        error_kw=dict(elinewidth=1, ecolor='black'),
        bottom=[y[0] for y in total_srv_chn_time],
        label='Port Chain'
    )

    # ax_arr[0].plot(x + width / 2.0, [y[0] for y in total_srv_chn_time],
    #                # marker='o', markerfacecolor='None', markeredgewidth=0.5, markeredgecolor='black',
    #                color='green', lw=0.5, ls='--')

    # Plot port chain start time

    # Plot gap time
    ax_arr[1].bar(
        x + width / 2.0, [y[0] for y in total_gap_time], width, alpha=0.6,
        yerr=[y[1] for y in total_gap_time], color='red', edgecolor='black',
        error_kw=dict(elinewidth=1, ecolor='black')
    )

    ax_arr[1].set_xticks(x + width / 2.0)
    ax_arr[1].set_xticklabels(x, fontsize=font_size, fontname=font_name)
    ax_arr[1].set_xlim(0.5, 9)
    ax_arr[1].set_xlabel("Number of chained SF-server(s)",
                         fontsize=font_size, fontname=font_name)

    for ax in ax_arr:
        ax.set_ylabel("Second", fontsize=font_size, fontname=font_name)

    # Add legend for all axis
    for ax in (ax_arr[0], ):
        handles, labels = ax.get_legend_handles_labels()
        ax.legend(handles, labels, fontsize=font_size,
                  loc='best')

        # ax.grid()

    # fig_s.savefig('./sfc_start_time.png', dpi=500, bbox_inches='tight')
    fig_s.savefig('./sfc_start_time.png', dpi=500)


def plot_start_three_compute(inc_wait=True):
    """Plot start time results on three compute nodes"""

    tex.setup(width=1, height=None, span=False, l=0.15, r=0.98, t=0.98, b=0.17,
              params={
                  'hatch.linewidth': 0.5
              })

    test_round = 30

    ##########
    #  Calc  #
    ##########

    min_sf_num = 1
    max_sf_num = 10

    result_map = dict()  # key is method

    method_tuple = ('ns', 'fn', 'nsrd')
    ts_info_tuple = (
        'SFI launching duration',
        'SFI booting duration',
        # 'SFI reordering duration',
        'PC building duration'
    )
    if not inc_wait:
        ts_info_tuple = (
            'SFI launching duration',
            'SFI booting duration',
            'PC building duration'
        )

    base_path = './test_result/three_compute/'

    for method in method_tuple:
        srv_num_result = list()
        for srv_num in range(min_sf_num, max_sf_num + 1):
            ctl_fn = '%s-sfc-ts-ctl-%d.csv' % (method, srv_num)
            ctl_csvp = os.path.join(base_path, ctl_fn)
            ctl_data = np.genfromtxt(ctl_csvp, delimiter=',')
            if ctl_data.shape[0] < test_round:
                raise RuntimeError(
                    'Number of test rounds is wrong, path: %s' % ctl_csvp
                )
            ctl_data = ctl_data[:test_round, :]
            if not inc_wait:
                srv_num_result.append(
                    [np.average(ctl_data[:, x]) for x in (0, 2, 3)]
                )
            else:
                srv_num_result.append(
                    [np.average(ctl_data[:, x]) for x in (0, 1, 3)]
                )

        result_map[method] = srv_num_result

    ##########
    #  Plot  #
    ##########

    method_label_tuple = ('LB', 'LC', 'LBLC')

    fig, ax = plt.subplots()

    # Add some extra space for the second axis at the bottom
    # fig.subplots_adjust(bottom=0.2)
    # Move twinned axis ticks and label from top to bottom

    width = 0.25

    x = np.arange(min_sf_num, max_sf_num + 1, 1, dtype='int32')
    # hatch_typ = [' ', '/', '.']
    hatch_patterns = ('xxxx', '////', '++++', 'oooo', '*', 'o', 'O', '.')

    # MARK: I don't know hot to plot this better...
    for m_idx, method in enumerate(method_tuple):
        pos = 0 + m_idx * width
        result_lst = result_map[method]

        cmap = cm.get_cmap('tab10')
        colors = [cmap(x) for x in range(len(ts_info_tuple))]

        # MARK: Ugly code...
        for srv_num, ts_tuple in enumerate(result_lst):
            for t_idx, ts in enumerate(ts_tuple):
                rect = ax.bar(
                    srv_num + 1 + pos, ts_tuple[t_idx], width, alpha=0.8,
                    bottom=sum(ts_tuple[0:t_idx]), lw=0.6,
                    color=colors[t_idx], edgecolor='black',
                    label=ts_info_tuple[t_idx],
                    hatch=hatch_patterns[t_idx]
                )
                if t_idx == (len(ts_tuple) - 1):
                    autolabel_bar(ax, rect, -10, method_label_tuple[m_idx])
                # Add legend
                if method == method_tuple[0] and srv_num == 0:
                    handles, labels = ax.get_legend_handles_labels()
                    ax.legend(handles, labels, loc='best')

    ax.set_xlabel("Chain length")

    ax.axhline(y=-0.005, color='black', linestyle='-', lw=1)
    # ax.text(0.5, -0.03, 'SFC creation method',
    # verticalalignment='bottom', horizontalalignment='center',
    # transform=ax.transAxes,
    # color='black', fontsize=font_size)

    ax.spines["bottom"].set_position(("axes", -0.2))
    ax.tick_params(axis='x', which='both', length=0)
    ax.spines["bottom"].set_visible(False)
    ax.set_xticks(x + (width / 2.0) * (len(method_tuple) - 1))
    ax.set_xticklabels(x)
    # ax.set_xlim(0, 11)

    ax.set_ylabel("Rendering duration (s)")
    ax.set_ylim(0, 340)

    # ax.grid(linestyle='--', lw=0.5)
    ax.yaxis.grid(which='major', lw=0.5, ls='--')
    save_fig(fig, './sfc_start_time')
    fig.show()


def autolabel_bar(ax, rects, height, label):
    for rect in rects:
        ax.text(rect.get_x() + rect.get_width() / 2.0, 5 * height,
                label, fontsize=font_size - 3,
                ha='center', va='bottom',
                rotation='vertical'
                )


def _filter_outlier_gap(ins_data_arr):
    """Filter out outliers in gap time tests

    MARK: The problem is that, when SFC is deleted, the flow classifier is
    deleted firstly. Then no-chained packets come from the source very fast.
    Then there is still some delayed chained packets com from the old chain
    path, this could be seen as a wrong chain creation round.
    """

    MIN_SFC_START_TIME = 100  # second, got from start time tests

    del_row_idx = list()
    last_send_ts = ins_data_arr[0, 1]
    for idx, row in enumerate(ins_data_arr[1:, :]):
        if np.abs(row[1] - last_send_ts) < MIN_SFC_START_TIME:
            del_row_idx.append(idx + 1)
        last_send_ts = row[1]
    # print(del_row_idx)
    return np.delete(ins_data_arr, del_row_idx, axis=0)


def plot_gap_three_compute():
    """Plot gap time results on three compute node"""

    ##########
    #  Calc  #
    ##########

    min_sf_num = 1
    max_sf_num = 10

    result_map = dict()
    test_round = 30
    method_tuple = ('ns', 'fn', 'nsrd')
    base_path = './test_result/three_compute/'

    for method in method_tuple:
        srv_num_result = list()
        for srv_num in range(min_sf_num, max_sf_num + 1):
            ins_fn = '%s-sfc-ts-ins-%d.csv' % (method, srv_num)
            ins_csvp = os.path.join(base_path, ins_fn)
            ins_data = np.genfromtxt(ins_csvp, delimiter=',')
            if ins_data.shape[0] < test_round:
                raise RuntimeError(
                    'Number of test rounds is wrong, path: %s' % ins_csvp
                )
            if ins_data.shape[1] != srv_num + 4:
                raise RuntimeError(
                    'Number of timestamps is wrong, path: %s' % ins_csvp
                )
            else:
                ins_data = _filter_outlier_gap(ins_data)
                ins_data = ins_data[:test_round, :]
                print('[DEBUG] Method: %s, srv_num : %d after filter: %d' % (
                    method, srv_num,
                    ins_data.shape[0]))
                srv_num_result.append(
                    # MARK: first 'b' - last 'a'
                    np.average(np.subtract(ins_data[:, -2], ins_data[:, -1]))
                )

        result_map[method] = srv_num_result

    ##########
    #  Plot  #
    ##########
    tex.setup(width=1, height=None, span=False, l=0.15, r=0.98, t=0.98, b=0.17,
              params={
                  'hatch.linewidth': 0.5
              })

    method_label_tuple = ('LB',
                          'LC',
                          'LBLC')

    hatch_patterns = ('xxxx', '////', '++++', '*', 'o', 'O', '.')

    fig, ax = plt.subplots()
    width = 0.25

    colors = [cmap(x) for x in range(len(method_tuple))]

    for m_idx, method in enumerate(method_tuple):
        gt_lst = result_map[method]
        pos = 0 + m_idx * width
        x = [pos + x for x in range(min_sf_num, max_sf_num + 1)]
        ax.bar(
            x, gt_lst, width, alpha=0.8,
            color=colors[m_idx], edgecolor='black',
            label=method_label_tuple[m_idx],
            hatch=hatch_patterns[m_idx],
            lw=0.6
        )

    handles, labels = ax.get_legend_handles_labels()
    ax.legend(handles, labels, loc='best')

    ax.set_xlabel('Chain length')

    x = np.arange(min_sf_num, max_sf_num + 1, 1, dtype='int32')
    ax.set_xticks(x + (width / 2.0) * (len(method_tuple) - 1))
    ax.set_xticklabels(x)
    ax.set_ylabel("Gap duration (s)")

    ax.yaxis.grid(which='major', lw=0.5, ls='--')

    save_fig(fig, './sfc_gap_time')
    fig.show()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise RuntimeError('Missing options.')
    if sys.argv[1] == '-s':
        plot_single_node()
        plt.show()
    elif sys.argv[1] == '-msw':
        plot_start_three_compute(inc_wait=True)
        plt.show()
    elif sys.argv[1] == '-msnw':
        plot_start_three_compute(inc_wait=False)
        plt.show()
    elif sys.argv[1] == '-mg':
        plot_gap_three_compute()
        plt.show()
    else:
        raise RuntimeError('Hehe...')
