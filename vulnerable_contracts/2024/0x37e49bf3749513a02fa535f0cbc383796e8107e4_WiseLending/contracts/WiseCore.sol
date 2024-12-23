// SPDX-License-Identifier: -- WISE --

pragma solidity =0.8.23;

import "./MainHelper.sol";
import "./TransferHub/TransferHelper.sol";

abstract contract WiseCore is MainHelper, TransferHelper {

    /**
     * @dev Wrapper function combining pool
     * preparations for borrow and collaterals.
     * Bypassed when called by powerFarms or aaveHub.
     */
    function _prepareAssociatedTokens(
        uint256 _nftId,
        address _poolTokenLend,
        address _poolTokenBorrow
    )
        internal
        returns (
            address[] memory,
            address[] memory
        )
    {
        if (_byPassCase(msg.sender) == true) {
            return (
                new address[](0),
                new address[](0)
            );
        }

        return (
            _preparationTokens(
                positionLendTokenData,
                _nftId,
                _poolTokenLend
            ),
            _preparationTokens(
                positionBorrowTokenData,
                _nftId,
                _poolTokenBorrow
            )
        );
    }

    /**
     * @dev Core function combining withdraw
     * logic and security checks.
     */
    function _coreWithdrawToken(
        address _caller,
        uint256 _nftId,
        address _poolToken,
        uint256 _amount,
        uint256 _shares,
        bool _onBehalf
    )
        internal
    {
        (
            address[] memory lendTokens,
            address[] memory borrowTokens
        ) = _prepareAssociatedTokens(
            _nftId,
            _poolToken,
            ZERO_ADDRESS
        );

        WISE_SECURITY.checksWithdraw(
            _nftId,
            _caller,
            _poolToken,
            _amount
        );

        _coreWithdrawBare(
            _nftId,
            _poolToken,
            _amount,
            _shares
        );

        if (_onBehalf == true) {
            emit FundsWithdrawnOnBehalf(
                _caller,
                _nftId,
                _poolToken,
                _amount,
                _shares,
                block.timestamp
            );
        } else {
            emit FundsWithdrawn(
                _caller,
                _nftId,
                _poolToken,
                _amount,
                _shares,
                block.timestamp
            );
        }

        _curveSecurityChecks(
            lendTokens,
            borrowTokens
        );
    }

    /**
     * @dev Internal function combining deposit
     * logic, security checks and event emit.
     */
    function _handleDeposit(
        address _caller,
        uint256 _nftId,
        address _poolToken,
        uint256 _amount
    )
        internal
        returns (uint256)
    {
        uint256 shareAmount = calculateLendingShares(
            {
                _poolToken: _poolToken,
                _amount: _amount,
                _maxSharePrice: false
            }
        );

        if (shareAmount == 0) {
            revert ZeroSharesAssigned();
        }

        _checkDeposit(
            _nftId,
            _caller,
            _poolToken,
            _amount
        );

        _increasePositionLendingDeposit(
            _nftId,
            _poolToken,
            shareAmount
        );

        _updatePoolStorage(
            _poolToken,
            _amount,
            shareAmount,
            _increaseTotalPool,
            _increasePseudoTotalPool,
            _increaseTotalDepositShares
        );

        _addPositionTokenData(
            _nftId,
            _poolToken,
            hashMapPositionLending,
            positionLendTokenData
        );

        emit FundsDeposited(
            _caller,
            _nftId,
            _poolToken,
            _amount,
            shareAmount,
            block.timestamp
        );

        return shareAmount;
    }

    /**
     * @dev External wrapper for
     * {_checkPositionLocked}.
     */
    function checkPositionLocked(
        uint256 _nftId,
        address _caller
    )
        external
        view
    {
        _checkPositionLocked(
            _nftId,
            _caller
        );
    }

    /**
     * @dev Checks if a postion is locked
     * for powerFarms. Get skipped when
     * aaveHub or a powerFarm itself is
     * the {msg.sender}.
     */
    function _checkPositionLocked(
        uint256 _nftId,
        address _caller
    )
        internal
        view
    {
        if (_byPassCase(_caller) == true) {
            return;
        }

        if (positionLocked[_nftId] == false) {
            return;
        }

        revert PositionLocked();
    }

    /**
     * @dev External wrapper for
     * {_checkDeposit}.
     */
    function checkDeposit(
        uint256 _nftId,
        address _caller,
        address _poolToken,
        uint256 _amount
    )
        external
        view
    {
        _checkDeposit(
            _nftId,
            _caller,
            _poolToken,
            _amount
        );
    }

    /**
     * @dev Internal function including
     * security checks for deposit logic.
     */
    function _checkDeposit(
        uint256 _nftId,
        address _caller,
        address _poolToken,
        uint256 _amount
    )
        internal
        view
    {
        _checkPositionLocked(
            _nftId,
            _caller
        );

        if (WISE_ORACLE.chainLinkIsDead(_poolToken) == true) {
            revert DeadOracle();
        }

        _checkMaxDepositValue(
            _poolToken,
            _amount
        );
    }

    /**
     * @dev Internal function checking
     * if the deposit amount for the
     * pool token is reached.
     */
    function _checkMaxDepositValue(
        address _poolToken,
        uint256 _amount
    )
        internal
        view
    {
        bool state = maxDepositValueToken[_poolToken]
            < globalPoolData[_poolToken].totalBareToken
            + lendingPoolData[_poolToken].pseudoTotalPool
            + _amount;

        if (state == true) {
            revert InvalidAction();
        }
    }

    /**
     * @dev Low level core function combining
     * pure withdraw math (without security
     * checks).
     */
    function _coreWithdrawBare(
        uint256 _nftId,
        address _poolToken,
        uint256 _amount,
        uint256 _shares
    )
        private
    {
        _updatePoolStorage(
            _poolToken,
            _amount,
            _shares,
            _decreaseTotalPool,
            _decreasePseudoTotalPool,
            _decreaseTotalDepositShares
        );

        _decreaseLendingShares(
            _nftId,
            _poolToken,
            _shares
        );

        _removeEmptyLendingData(
            _nftId,
            _poolToken
        );
    }

    /**
     * @dev Core function combining borrow
     * logic with security checks.
     */
    function _coreBorrowTokens(
        address _caller,
        uint256 _nftId,
        address _poolToken,
        uint256 _amount,
        uint256 _shares,
        bool _onBehalf
    )
        internal
    {
        (
            address[] memory lendTokens,
            address[] memory borrowTokens
        ) = _prepareAssociatedTokens(
            _nftId,
            ZERO_ADDRESS,
            _poolToken
        );

        WISE_SECURITY.checksBorrow(
            _nftId,
            _caller,
            _poolToken,
            _amount
        );

        _updatePoolStorage(
            _poolToken,
            _amount,
            _shares,
            _increasePseudoTotalBorrowAmount,
            _decreaseTotalPool,
            _increaseTotalBorrowShares
        );

        _increaseMappingValue(
            userBorrowShares,
            _nftId,
            _poolToken,
            _shares
        );

        _addPositionTokenData(
            _nftId,
            _poolToken,
            hashMapPositionBorrow,
            positionBorrowTokenData
        );

        if (_onBehalf == true) {
            emit FundsBorrowedOnBehalf(
                _caller,
                _nftId,
                _poolToken,
                _amount,
                _shares,
                block.timestamp
            );
        } else {
            emit FundsBorrowed(
                _caller,
                _nftId,
                _poolToken,
                _amount,
                _shares,
                block.timestamp
            );
        }

        _curveSecurityChecks(
            lendTokens,
            borrowTokens
        );
    }

    /**
     * @dev Internal math function for liquidation logic
     * caluclating amount to withdraw from pure
     * collateral for liquidation.
     */
    function _withdrawPureCollateralLiquidation(
        uint256 _nftId,
        address _poolToken,
        uint256 _percentLiquidation
    )
        private
        returns (uint256 transferAmount)
    {
        transferAmount = _percentLiquidation
            * pureCollateralAmount[_nftId][_poolToken]
            / PRECISION_FACTOR_E18;

        _decreasePositionMappingValue(
            pureCollateralAmount,
            _nftId,
            _poolToken,
            transferAmount
        );

        _decreaseTotalBareToken(
            _poolToken,
            transferAmount
        );
    }

    /**
     * @dev Internal math function for liquidation logic
     * which checks if pool has enough token to pay out
     * liquidator. If not, liquidator get corresponding
     * shares for later withdraw.
     */
    function _withdrawOrAllocateSharesLiquidation(
        uint256 _nftId,
        uint256 _nftIdLiquidator,
        address _poolToken,
        uint256 _percentWishCollateral
    )
        private
        returns (uint256)
    {
        uint256 cashoutShares = _percentWishCollateral
            * userLendingData[_nftId][_poolToken].shares
            / PRECISION_FACTOR_E18;

        uint256 withdrawAmount = cashoutAmount(
            _poolToken,
            cashoutShares
        );

        uint256 totalPoolToken = globalPoolData[_poolToken].totalPool;

        if (withdrawAmount <= totalPoolToken) {

            _coreWithdrawBare(
                _nftId,
                _poolToken,
                withdrawAmount,
                cashoutShares
            );

            return withdrawAmount;
        }

        uint256 totalPoolInShares = calculateLendingShares(
            {
                _poolToken: _poolToken,
                _amount: totalPoolToken,
                _maxSharePrice: true
            }
        );

        uint256 shareDifference = cashoutShares
            - totalPoolInShares;

        _coreWithdrawBare(
            _nftId,
            _poolToken,
            totalPoolToken,
            totalPoolInShares
        );

        _decreaseLendingShares(
            _nftId,
            _poolToken,
            shareDifference
        );

        _increasePositionLendingDeposit(
            _nftIdLiquidator,
            _poolToken,
            shareDifference
        );

        _addPositionTokenData(
            _nftId,
            _poolToken,
            hashMapPositionLending,
            positionLendTokenData
        );

        return totalPoolToken;
    }

    /**
     * @dev Internal math function combining functionallity
     * of {_withdrawPureCollateralLiquidation} and
     * {_withdrawOrAllocateSharesLiquidation}.
     */
    function _calculateReceiveAmount(
        uint256 _nftId,
        uint256 _nftIdLiquidator,
        address _receiveTokens,
        uint256 _removePercentage
    )
        private
        returns (uint256)
    {
        uint256 receiveAmount = _withdrawPureCollateralLiquidation(
            _nftId,
            _receiveTokens,
            _removePercentage
        );

        if (userLendingData[_nftId][_receiveTokens].unCollateralized == true) {
            return receiveAmount;
        }

        return _withdrawOrAllocateSharesLiquidation(
            _nftId,
            _nftIdLiquidator,
            _receiveTokens,
            _removePercentage
        ) + receiveAmount;
    }

    /**
     * @dev Core liquidation function for
     * security checks and liquidation math.
     */
    function _coreLiquidation(
        CoreLiquidationStruct memory _data
    )
        internal
        returns (uint256 receiveAmount)
    {
        uint256 collateralPercentage = WISE_SECURITY.calculateWishPercentage(
            _data.nftId,
            _data.tokenToRecieve,
            WISE_ORACLE.getTokensInETH(
                _data.tokenToPayback,
                _data.paybackAmount
            ),
            _data.maxFeeETH,
            _data.baseRewardLiquidation
        );

        if (collateralPercentage > PRECISION_FACTOR_E18) {
            revert CollateralTooSmall();
        }

        _corePayback(
            _data.nftId,
            _data.tokenToPayback,
            _data.paybackAmount,
            _data.shareAmountToPay
        );

        receiveAmount = _calculateReceiveAmount(
            _data.nftId,
            _data.nftIdLiquidator,
            _data.tokenToRecieve,
            collateralPercentage
        );

        WISE_SECURITY.checkBadDebt(
            _data.nftId
        );

        _curveSecurityChecks(
            _data.lendTokens,
            _data.borrowTokens
        );

        _safeTransferFrom(
            _data.tokenToPayback,
            _data.caller,
            address(this),
            _data.paybackAmount
        );

        _safeTransfer(
            _data.tokenToRecieve,
            _data.receiver,
            receiveAmount
        );
    }
}
