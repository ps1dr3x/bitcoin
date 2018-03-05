// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/coinselection.h>
#include <util.h>
#include <utilmoneystr.h>

// Descending order comparator
struct {
    bool operator()(const CInputCoin& a, const CInputCoin& b) const
    {
        return a.effective_value > b.effective_value;
    }
} descending;

/*
 * This is the Branch and Bound Coin Selection algorithm designed by Murch. It searches for an input set that can pay for the
 * spending target and does not exceed the spending target by more than the cost of creating and spending a change output. The
 * algorithm uses a depth-first search on a binary tree. In the binary tree, each node corresponds to the inclusion or the omission
 * of a UTXO. UTXOs are sorted by their effective values and the trees is explored deterministically per the inclusion branch first.
 * At each node, the algorithm checks whether the selection is within the target range. While the selection has not reached the
 * target range, more UTXOs are included. When a selection's value exceeds the target range, the complete subtree deriving from
 * this selection can be omitted. At that point, the last included UTXO is deselected and the corresponding omission branch explored
 * instead. The search ends after the complete tree has been searched or after a limited number of tries.
 *
 * The search continues to search for better solutions after one solution has been found. The best solution is chosen by minimizing
 * the waste metric. The waste metric is defined as the cost to spend the current inputs at the given fee rate minus the long
 * term expected cost to spend the inputs, plus the amount the selection exceeds the spending target:
 *
 * waste = selectionTotal - target + inputs × (currentFeeRate - longTermFeeRate)
 *
 * The algorithm uses two additional optimizations. A lookahead keeps track of the total value of the unexplored UTXOs. A subtree
 * is not explored if the lookahead indicates that the target range cannot be reached. Further, it is unnecessary to test
 * equivalent combinations. This allows us to skip testing the inclusion of UTXOs that match the effective value and waste of an
 * omitted predecessor.
 *
 * The Branch and Bound algorithm is described in detail in Murch's Master Thesis: https://murch.one/wp-content/uploads/2016/11/erhardt2016coinselection.pdf
 *
 * @param const std::vector<CInputCoin>& utxo_pool -> The set of UTXOs that we are choosing from. These UTXOs will be sorted in descending order
 *                                             by effective value and the CInputCoins' values are their effective values.
 * @param const CAmount& target_value -> This is the value that we want to select. It is the lower bound of the range.
 * @param const CAmount& cost_of_change -> This is the cost of creating and spending a change output. This plus target_value is the upper bound
 *                                  of the range.
 * @param std::set<CInputCoin>& out_set -> This is an output parameter for the set of CInputCoins that have been selected.
 * @param CAmount& value_ret -> This is an output parameter for the total value of the CInputCoins that were selected.
 * @param CAmount not_input_fees -> The fees that need to be paid for the outputs and fixed size overhead (version, locktime, marker and flag)
 */

static const size_t TOTAL_TRIES = 100000;

bool SelectCoinsBnB(std::vector<CInputCoin>& utxo_pool, const CAmount& target_value, const CAmount& cost_of_change, std::set<CInputCoin>& out_set, CAmount& value_ret, CAmount not_input_fees)
{
    out_set.clear();
    CAmount value_track = 0;

    int depth = 0;
    std::vector<bool> selection(utxo_pool.size()); // select the utxo at this index
    bool backtrack = false;
    CAmount actual_target = not_input_fees + target_value;

    // Calculate lookahead
    CAmount lookahead = 0;
    for (const CInputCoin& utxo : utxo_pool) {
        lookahead += utxo.effective_value;
    }
    if (lookahead < actual_target) {
        return false;
    }

    // Sort the utxo_pool
    std::sort(utxo_pool.begin(), utxo_pool.end(), descending);

    // Best solution
    CAmount curr_waste = 0;
    std::vector<bool> best_selection;
    CAmount best_waste = MAX_MONEY;

    // Depth First search loop for choosing the UTXOs
    for (size_t i = 0; i < TOTAL_TRIES; ++i) {
        // Conditions for starting a backtrack
        if (value_track + lookahead < actual_target ||                // Cannot possibly reach target with the amount remaining in the lookahead.
            value_track > actual_target + cost_of_change ||    // Selected value is out of range, go back and try other branch
            (curr_waste > best_waste && (utxo_pool.at(0).fee - utxo_pool.at(0).long_term_fee) > 0)) { // Don't select things which we know will be more wasteful if the waste is increasing
            backtrack = true;
        } else if (value_track >= actual_target) {       // Selected value is within range
            curr_waste += (value_track - actual_target); // This is the excess value which is added to the waste for the below comparison
            // Adding another UTXO after this check could bring the waste down if the long term fee is higher than the current fee.
            // However we are not going to explore that because this optimization for the waste is only done when we have hit our target
            // value. Adding any more UTXOs will be just burning the UTXO; it will go entirely to fees. Thus we aren't going to
            // explore any more UTXOs to avoid burning money like that.
            if (curr_waste <= best_waste) {
                best_selection.assign(selection.begin(), selection.end());
                best_waste = curr_waste;
            }
            curr_waste -= (value_track - actual_target); // Remove the excess value as we will be selecting different coins now
            backtrack = true;
        }

        // Backtracking, moving backwards
        if (backtrack) {
            backtrack = false; // Reset
            --depth;

            // Walk backwards to find the last included UTXO that still needs to have its omission branch traversed.
            while (depth >= 0 && !selection.at(depth)) {
                // Step back one
                lookahead += utxo_pool.at(depth).effective_value;
                --depth;
            }
            if (depth < 0) { // We have walked back to the first utxo and no branch is untraversed. All solutions searched
                break;
            }

            // These were always included first, try excluding now
            selection.at(depth) = false;
            value_track -= utxo_pool.at(depth).effective_value;
            curr_waste -= (utxo_pool.at(depth).fee - utxo_pool.at(depth).long_term_fee);
            ++depth;
        } else { // Moving forwards, continuing down this branch
            // Assert that this utxo is not negative. It should never be negative, effective value calculation should have removed it
            assert(utxo_pool.at(depth).effective_value > 0);

            // Avoid searching a branch if the previous UTXO has the same value and same waste and was excluded. Since the ratio of fee to
            // long term fee is the same, we only need to check if one of those values match in order to know that the waste is the same.
            if (depth > 0 && !selection.at(depth - 1) &&
                utxo_pool.at(depth).effective_value == utxo_pool.at(depth - 1).effective_value &&
                utxo_pool.at(depth).fee == utxo_pool.at(depth - 1).fee) {
                selection.at(depth) = false;
                lookahead -= utxo_pool.at(depth).effective_value;
                ++depth;
            } else {
                // Remove this utxo from the lookahead utxo amount
                lookahead -= utxo_pool.at(depth).effective_value;
                // Increase waste
                curr_waste += (utxo_pool.at(depth).fee - utxo_pool.at(depth).long_term_fee);
                // Inclusion branch first (Largest First Exploration)
                selection.at(depth) = true;
                value_track += utxo_pool.at(depth).effective_value;
                ++depth;
            }
        }
    }

    // Check for solution
    if (best_selection.empty()) {
        return false;
    }

    // Set output set
    value_ret = 0;
    for (size_t i = 0; i < best_selection.size(); ++i) {
        if (best_selection.at(i)) {
            out_set.insert(utxo_pool.at(i));
            value_ret += utxo_pool.at(i).txout.nValue;
        }
    }

    return true;
}
