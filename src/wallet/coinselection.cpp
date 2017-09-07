// Copyright (c) 2012-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/coinselection.h"
#include "util.h"
#include "utilmoneystr.h"

// Descending order comparator
struct {
    bool operator()(const CInputCoin& a, const CInputCoin& b) const
    {
        return a.txout.nValue > b.txout.nValue;
    }
} descending;

/*
 * This is the Branch and Bound Coin Selection algorithm designed by Mark Erhardt. It is an exact match algorithm where the exact match
 * is a range with the lower bound being the value we want to spend and the upper bound being that value plus the additional cost
 * required to create and spend a change output. To do this, the algorithm builds a binary tree where each node is a UTXO and whether
 * that UTXO is included or not in the current coin selection. The tree is searched in include-first order. Each UTXO is first included
 * and the current selection is evaluated for whether it is within the current threshold. If it is over the threshold, we try excluding
 * the UTXO previously added and the branch of the tree involving its inclusion is then not explored. This process is repeated until
 * a solution is found (i.e. selected value falls within the range), the exhaustion limit is reached, or the tree is exhausted and no
 * solution was found.
 *
 * To find the best possible solution, we use a waste metric. The waste metric is defined as the cost to spend the current inputs
 * now minus the cost to spend the current inputs later, plus the amount exceeding the target value. We search the tree to find the
 * set of UTXOs which falls within our range and minimizes waste.
 *
 * An additional optimization of this algorithm implemented here is a lookahead value which maintains the total value of the UTXO set
 * of all unexplored UTXOs (i.e. UTXOs that have not yet been included or excluded). This allows us to cut a branch if the remaining
 * amount is not sufficient to reach our target.
 *
 * SelectCoinsBnB Arguments:
 * const std::vector<CInputCoin>& utxo_pool -> The set of UTXOs that we are choosing from. These UTXOs will be sorted in descending order
 *                                             and the CInputCoins' values are their effective values.
 * const CAmount& target_value -> This is the value that we want to select. It is the lower bound of the range.
 * const CAmount& cost_of_change -> This is the cost of creating and spending a change output. This plus target_value is the upper bound
 *                                  of the range.
 * std::set<CInputCoin>& out_set -> This is an output parameter for the set of CInputCoins that have been selected.
 * CAmount& value_ret -> This is an output parameter for the total value of the CInputCoins that were selected.
 * CAmount& fee_ret -> This is an output parameter for the value of the transaction fees for the CInputCoins that were selected.
 */

bool SelectCoinsBnB(std::vector<CInputCoin>& utxo_pool, const CAmount& target_value, const CAmount& cost_of_change, std::set<CInputCoin>& out_set, CAmount& value_ret, CAmount& fee_ret)
{
    out_set.clear();
    value_ret = 0;

    if (utxo_pool.empty()) {
        return false;
    }

    int depth = 0;
    int remaining_tries = 100000;
    std::vector<std::pair<bool, bool>> selection; // First bool: select the utxo at this index; Second bool: traversing exclusion branch of this utxo
    selection.assign(utxo_pool.size(), std::pair<bool, bool>(false, false));
    bool done = false;
    bool backtrack = false;

    // Sort the utxo_pool
    std::sort(utxo_pool.begin(), utxo_pool.end(), descending);

    // Calculate lookahead
    CAmount lookahead = 0;
    for (const CInputCoin& utxo : utxo_pool) {
        lookahead += utxo.txout.nValue;
    }

    // Best solution
    CAmount curr_waste = 0;
    std::vector<std::pair<bool, bool>> best_selection;
    CAmount best_waste = MAX_MONEY;

    // Depth First search loop for choosing the UTXOs
    while (!done)
    {
        if (remaining_tries <= 0) { // Too many tries, exit
            break;
        } else if (value_ret > target_value + cost_of_change) { // Selected value is out of range, go back and try other branch
            backtrack = true;
        } else if (curr_waste > best_waste) { // Don't select things which we know will be more wasteful
            backtrack = true;
        } else if (value_ret >= target_value) { // Selected value is within range
            curr_waste += (value_ret - target_value); // This is the excess value which is added to the waste for the below comparison
            if (curr_waste <= best_waste) {
                best_selection.assign(selection.begin(), selection.end());
                best_waste = curr_waste;
            }
            curr_waste -= (value_ret - target_value); // Remove the excess value as we will be selecting different coins now
            backtrack = true;
        } else if (depth >= (int)utxo_pool.size()) { // Reached a leaf node, no solution here
            backtrack = true;
        } else if (value_ret + lookahead < target_value) { // Cannot possibly reach target with the amount remaining in the lookahead
            if (depth == 0) { // At the first utxo, no possible selections, so exit
                break;
            } else {
                backtrack = true;
            }
        } else { // Continue down this branch
            // Assert that this utxo is not negative. It should never be negative, effective value calculation should have removed it
            assert(utxo_pool.at(depth).txout.nValue >= 0);

            // Remove this utxo from the lookahead utxo amount
            lookahead -= utxo_pool.at(depth).txout.nValue;
            // Increase waste
            curr_waste += (utxo_pool.at(depth).fee - utxo_pool.at(depth).long_term_fee);
            // Inclusion branch first (Largest First Exploration)
            selection.at(depth).first = true;
            value_ret += utxo_pool.at(depth).txout.nValue;
            ++depth;
        }

        // Step back to the previous utxo and try the other branch
        if (backtrack) {
            backtrack = false; // Reset
            --depth;

            // Walk backwards to find the first utxo which has not has its second branch traversed
            while (selection.at(depth).second) {
                selection.at(depth).first = false;
                selection.at(depth).second = false;
                lookahead += utxo_pool.at(depth).txout.nValue;

                // Step back one
                --depth;

                if (depth < 0) { // We have walked back to the first utxo and no branch is untraversed. No solution, exit.
                    done = true;
                    break;
                }
            }

            if (!done) {
                // Now traverse the second branch of the utxo we have arrived at.
                selection.at(depth).second = true;

                // These were always included first, try excluding now
                selection.at(depth).first = false;
                value_ret -= utxo_pool.at(depth).txout.nValue;
                curr_waste -= (utxo_pool.at(depth).fee - utxo_pool.at(depth).long_term_fee);
                ++depth;
            }
        }
        --remaining_tries;
    }

    // Check for solution
    if (best_selection.empty()) {
        return false;
    }

    // Set output set
    value_ret = 0;
    for (unsigned int i = 0; i < best_selection.size(); ++i) {
        if (best_selection.at(i).first) {
            out_set.insert(utxo_pool.at(i));
            fee_ret += utxo_pool.at(i).fee;
            value_ret += utxo_pool.at(i).txout.nValue;
        }
    }

    return true;
}

static void ApproximateBestSubset(const std::vector<CInputCoin>& vValue, const CAmount& nTotalLower, const CAmount& nTargetValue,
                                  std::vector<char>& vfBest, CAmount& nBest, int iterations = 1000)
{
    std::vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    nBest = nTotalLower;

    FastRandomContext insecure_rand;

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        CAmount nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (unsigned int i = 0; i < vValue.size(); i++)
            {
                //The solver here uses a randomized algorithm,
                //the randomness serves no real security purpose but is just
                //needed to prevent degenerate behavior and it is important
                //that the rng is fast. We do not use a constant random sequence,
                //because there may be some privacy improvement by making
                //the selection random.
                if (nPass == 0 ? insecure_rand.randbool() : !vfIncluded[i])
                {
                    nTotal += vValue[i].txout.nValue;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].txout.nValue;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }
}

bool KnapsackSolver(std::vector<CInputCoin>& utxo_pool, const CAmount& nTargetValue, std::set<CInputCoin>& out_set, CAmount& value_ret)
{
    out_set.clear();
    value_ret = 0;

    // List of values less than target
    boost::optional<CInputCoin> coinLowestLarger;
    std::vector<CInputCoin> vValue;
    CAmount nTotalLower = 0;

    random_shuffle(utxo_pool.begin(), utxo_pool.end(), GetRandInt);

    for (const CInputCoin coin : utxo_pool)
    {
        if (coin.txout.nValue == nTargetValue)
        {
            out_set.insert(coin);
            value_ret += coin.txout.nValue;
            return true;
        }
        else if (coin.txout.nValue < nTargetValue + MIN_CHANGE)
        {
            vValue.push_back(coin);
            nTotalLower += coin.txout.nValue;
        }
        else if (!coinLowestLarger || coin.txout.nValue < coinLowestLarger->txout.nValue)
        {
            coinLowestLarger = coin;
        }
    }

    if (nTotalLower == nTargetValue)
    {
        for (const auto& input : vValue)
        {
            out_set.insert(input);
            value_ret += input.txout.nValue;
        }
        return true;
    }

    if (nTotalLower < nTargetValue)
    {
        if (!coinLowestLarger)
            return false;
        out_set.insert(coinLowestLarger.get());
        value_ret += coinLowestLarger->txout.nValue;
        return true;
    }

    // Solve subset sum by stochastic approximation
    std::sort(vValue.begin(), vValue.end(), descending);
    std::vector<char> vfBest;
    CAmount nBest;

    ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest);
    if (nBest != nTargetValue && nTotalLower >= nTargetValue + MIN_CHANGE)
        ApproximateBestSubset(vValue, nTotalLower, nTargetValue + MIN_CHANGE, vfBest, nBest);

    // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
    //                                   or the next bigger coin is closer), return the bigger coin
    if (coinLowestLarger &&
        ((nBest != nTargetValue && nBest < nTargetValue + MIN_CHANGE) || coinLowestLarger->txout.nValue <= nBest))
    {
        out_set.insert(coinLowestLarger.get());
        value_ret += coinLowestLarger->txout.nValue;
    }
    else {
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
            {
                out_set.insert(vValue[i]);
                value_ret += vValue[i].txout.nValue;
            }

        if (LogAcceptCategory(BCLog::SELECTCOINS)) {
            LogPrint(BCLog::SELECTCOINS, "SelectCoins() best subset: ");
            for (unsigned int i = 0; i < vValue.size(); i++) {
                if (vfBest[i]) {
                    LogPrint(BCLog::SELECTCOINS, "%s ", FormatMoney(vValue[i].txout.nValue));
                }
            }
            LogPrint(BCLog::SELECTCOINS, "total %s\n", FormatMoney(nBest));
        }
    }

    return true;
}
