# Issue H-1: Cross-contract reentrancy allows YIELD_TOKEN theft for the `GenericERC4626` `WithdrawalRequestManager` variant 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/73 

## Found by 
KungFuPanda, Ragnarok, xiaoming90

- https://github.com/notional-finance/leveraged-vaults/blob/7e0abc3e118db0abb20c7521c6f53f1762fdf562/contracts/trading/adapters/UniV3Adapter.sol#L60-L72


^ The only validations in-place are the tokenIn and tokenOut sanitizations, but not the whole multihop path though.

<img width="815" height="481" alt="Image" src="https://sherlock-files.ams3.digitaloceanspaces.com/gh-images/b8f9b6b7-8401-4160-aa5a-c678f49bb7f7" />

_NOTE_ This is the Trading module we have: https://etherscan.io/address/0x179a2d2408bfbc21b72d59c4a74e5010f07dc823#code

![Image](https://sherlock-files.ams3.digitaloceanspaces.com/gh-images/b2d7e6ee-c3ab-44b9-bb85-1986f4418d07)

https://etherscan.io/address/0xE592427A0AEce92De3Edee1F18E0157C05861564#code <-- UniswapV3 router

## Description
Since the `WithdrawalRequestManager` allows `onlyVault` operations for multiple different strategy "vaults",..

A combination of a default reentrancy + cross-contract reentrancy is possible...

...Through which `YIELD_TOKEN`s can be drained from the `WithdrawalRequestManager`...

...---> to the yield strategy where the strategy's `depositAsset != WithdrawalRequestManager.STAKE_TOKEN`.

This way, the strategy will record a higher surplus (aka delta) of `YIELD_TOKEN`s in the current `YIELD_TOKEN.balanceOf(address(this))` and will mint more shares to the malicious user's account.



`onlyApprovedVault` permits any caller whitelisted in the `isApprovedVault` mapping:
```solidity
    /// @dev Ensures that only approved vaults can initiate withdraw requests.
    modifier onlyApprovedVault() {
        if (!isApprovedVault[msg.sender]) revert Unauthorized(msg.sender);
        _;
    }
```

Thus, it is possible to steal funds from the `WithdrawalRequestManager` and then burn these `YIELD_TOKEN`s in exchange for deposit underlying staking token assets.



## Root cause
A single `WithdrawalRequestManager` permits multiple `AbstractYieldStrategy` instances (aka "whitelisted vaults").

Since neither the `WithdrawalRequestManager.stakeTokens` nor `WithdrawalRequestManager.initiateWithdraw` functions have a `nonReentrant` modifier or an equivalent cross-contract reentrancy protection method, the 


```solidity
    function _initiateWithdraw(
        address account,
        uint256 yieldTokenAmount,
        uint256 sharesHeld,
        bytes memory data
    ) internal override virtual returns (uint256 requestId) {
        ERC20(yieldToken).approve(address(withdrawRequestManager), yieldTokenAmount);
        requestId = withdrawRequestManager.initiateWithdraw({ // audit: reentrancy here!!!!
            account: account, yieldTokenAmount: yieldTokenAmount, sharesAmount: sharesHeld, data: data
        });
    } // audit: does this affect the yield token balance somehow?

    /// @dev By default we can use the withdraw request manager to stake the tokens
    function _mintYieldTokens(uint256 assets, address /* receiver */, bytes memory depositData) internal override virtual { // audit: can it be reentered to increase the yieldtoken balance somehow???
        ERC20(asset).approve(address(withdrawRequestManager), assets); // audit: reverts for USDT
        withdrawRequestManager.stakeTokens(address(asset), assets, depositData); // audit malicious data
    }
```


```solidity

    /// @inheritdoc IWithdrawRequestManager
    function stakeTokens(
        address depositToken,
        uint256 amount,
        bytes calldata data // audit
    ) external override onlyApprovedVault returns (uint256 yieldTokensMinted) { // @audit: should actually be non reentrant I think
        uint256 initialYieldTokenBalance = ERC20(YIELD_TOKEN).balanceOf(address(this));
        ERC20(depositToken).safeTransferFrom(msg.sender, address(this), amount);
        (uint256 stakeTokenAmount, bytes memory stakeData) = _preStakingTrade(depositToken, amount, data); // audit: reenter and call initiateWithdraw from a diffferent vault (i.e., cross-contract reentrancy)
        _stakeTokens(stakeTokenAmount, stakeData);



        yieldTokensMinted = ERC20(YIELD_TOKEN).balanceOf(address(this)) - initialYieldTokenBalance; // audit: REENTRANCY HERE??? 🪻🪻🪻
        ERC20(YIELD_TOKEN).safeTransfer(msg.sender, yieldTokensMinted);
    }
    

    /// @inheritdoc IWithdrawRequestManager
    function initiateWithdraw(
        address account,
        uint256 yieldTokenAmount,
        uint256 sharesAmount,
        bytes calldata data
    ) external override onlyApprovedVault returns (uint256 requestId) {
        WithdrawRequest storage accountWithdraw = s_accountWithdrawRequest[msg.sender][account];
        if (accountWithdraw.requestId != 0) revert ExistingWithdrawRequest(msg.sender, account, accountWithdraw.requestId);

        // Receive the requested amount of yield tokens from the approved vault.
        ERC20(YIELD_TOKEN).safeTransferFrom(msg.sender, address(this), yieldTokenAmount); // audit: exchanging yieldtoken for the underlying assets

        requestId = _initiateWithdrawImpl(account, yieldTokenAmount, data); // audit: reentrancy here??? through forceWithdraw(...)???
        accountWithdraw.requestId = requestId;
        accountWithdraw.yieldTokenAmount = yieldTokenAmount.toUint120();
        accountWithdraw.sharesAmount = sharesAmount.toUint120();
        s_tokenizedWithdrawRequest[requestId] = TokenizedWithdrawRequest({
            totalYieldTokenAmount: yieldTokenAmount.toUint120(), // audit: may be outdated
            totalWithdraw: 0,
            finalized: false
        });

        emit InitiateWithdrawRequest(account, msg.sender, yieldTokenAmount, sharesAmount, requestId);
    }

```

```solidity
/ @dev Used for ERC4626s that can be staked and unstaked on demand without any additional
/// time constraints.
contract GenericERC4626WithdrawRequestManager is AbstractWithdrawRequestManager {

    uint256 private currentRequestId;
    mapping(uint256 => uint256) private s_withdrawRequestShares;

    constructor(address _erc4626)
        AbstractWithdrawRequestManager(IERC4626(_erc4626).asset(), _erc4626, IERC4626(_erc4626).asset()) { }

    function _initiateWithdrawImpl(
        address /* account */,
        uint256 sharesToWithdraw,
        bytes calldata /* data */
    ) override internal returns (uint256 requestId) {
        requestId = ++currentRequestId;
        s_withdrawRequestShares[requestId] = sharesToWithdraw;
    }

    function _stakeTokens(uint256 amount, bytes memory /* stakeData */) internal override {
        ERC20(STAKING_TOKEN).approve(address(YIELD_TOKEN), amount);
        IERC4626(YIELD_TOKEN).deposit(amount, address(this));
    }

    function _finalizeWithdrawImpl(
        address /* account */,
        uint256 requestId
    ) internal override returns (uint256 tokensClaimed, bool finalized) {
        uint256 sharesToRedeem = s_withdrawRequestShares[requestId];
        delete s_withdrawRequestShares[requestId];
        tokensClaimed = IERC4626(YIELD_TOKEN).redeem(sharesToRedeem, address(this), address(this));
        finalized = true;
        // audit: increases the yieldtoken balance
    }

    function canFinalizeWithdrawRequest(uint256 /* requestId */) public pure override returns (bool) {
        return true;
    }
}
```

## Attack path

When the `WithdrawalRequestManager` is using the `GenericERC4626` functionality variant:..

```solidity
/ @dev Used for ERC4626s that can be staked and unstaked on demand without any additional
/// time constraints.
contract GenericERC4626WithdrawRequestManager is AbstractWithdrawRequestManager {

    uint256 private currentRequestId;
    mapping(uint256 => uint256) private s_withdrawRequestShares;

    constructor(address _erc4626)
        AbstractWithdrawRequestManager(IERC4626(_erc4626).asset(), _erc4626, IERC4626(_erc4626).asset()) { }

    function _initiateWithdrawImpl(
        address /* account */,
        uint256 sharesToWithdraw,
        bytes calldata /* data */
    ) override internal returns (uint256 requestId) {
        requestId = ++currentRequestId;
        s_withdrawRequestShares[requestId] = sharesToWithdraw;
    }

    function _stakeTokens(uint256 amount, bytes memory /* stakeData */) internal override {
        ERC20(STAKING_TOKEN).approve(address(YIELD_TOKEN), amount);
        IERC4626(YIELD_TOKEN).deposit(amount, address(this));
    }

    function _finalizeWithdrawImpl(
        address /* account */,
        uint256 requestId
    ) internal override returns (uint256 tokensClaimed, bool finalized) {
        uint256 sharesToRedeem = s_withdrawRequestShares[requestId];
        delete s_withdrawRequestShares[requestId];
        tokensClaimed = IERC4626(YIELD_TOKEN).redeem(sharesToRedeem, address(this), address(this));
        finalized = true;
        // audit: increases the yieldtoken balance
    }

    function canFinalizeWithdrawRequest(uint256 /* requestId */) public pure override returns (bool) {
        return true;
    }
}
```

... The users who request redemptions (via `initiateWithdraw`) just temporarily leave sparse `YIELD_TOKEN`s in the `WithdrawalRequestManager`.

**It is a crucial observation needed for proving the validity of the suggested cross-contract reentrancy attack.**

## External preconditions
**Spare `YIELD_TOKEN`s in the `WithdrawalRequestManager`'s `GenericERC4626` variant as a result of other users calling `initateWithdraw` and leaving pending redemption requests.**

_NOTE_ **Either through front-running or just proper timing, the attack will be executed before the requester calls `finalizeAndRedeemWithdrawRequest` or `finalizeRequestManual` is called.**


1.
```solidity
        /// @inheritdoc ILendingRouter
    function enterPosition(
        address onBehalf,
        address vault,
        uint256 depositAssetAmount,
        uint256 borrowAmount,
        bytes calldata depositData
    ) public override isAuthorized(onBehalf, vault) {
        _enterPosition(onBehalf, vault, depositAssetAmount, borrowAmount, depositData, address(0));
    }

    function _enterPosition(
        address onBehalf,
        address vault,
        uint256 depositAssetAmount,
        uint256 borrowAmount,
        bytes memory depositData,
        address migrateFrom
    ) internal {
        address asset = IYieldStrategy(vault).asset();
        // Cannot enter a position if the account already has a native share balance
        if (IYieldStrategy(vault).balanceOf(onBehalf) > 0) revert CannotEnterPosition();

        if (depositAssetAmount > 0) {
            // Take any margin deposit from the sender initially
            ERC20(asset).safeTransferFrom(msg.sender, address(this), depositAssetAmount);
        }

        if (borrowAmount > 0) {
            _flashBorrowAndEnter(
                onBehalf, vault, asset, depositAssetAmount, borrowAmount, depositData, migrateFrom
            );
        } else {
            _enterOrMigrate(onBehalf, vault, asset, depositAssetAmount, depositData, migrateFrom);
        }

        ADDRESS_REGISTRY.setPosition(onBehalf, vault); // audit: the vault can be completely permissionless
    }

    /// @dev Enters a position or migrates shares from a previous lending router
    function _enterOrMigrate(
        address onBehalf,
        address vault,
        address asset,
        uint256 assetAmount,
        bytes memory depositData,
        address migrateFrom
    ) internal returns (uint256 sharesReceived) {
        if (migrateFrom != address(0)) {
            // Allow the previous lending router to repay the debt from assets held here.
            ERC20(asset).checkApprove(migrateFrom, assetAmount);
            sharesReceived = ILendingRouter(migrateFrom).balanceOfCollateral(onBehalf, vault);

            // Must migrate the entire position
            ILendingRouter(migrateFrom).exitPosition(
                onBehalf, vault, address(this), sharesReceived, type(uint256).max, bytes("")
            );
        } else {
            ERC20(asset).approve(vault, assetAmount);
            sharesReceived = IYieldStrategy(vault).mintShares(assetAmount, onBehalf, depositData); // @audit:reentrant
        }

        _supplyCollateral(onBehalf, vault, asset, sharesReceived);
    }
```


2. 
```solidity
     function mintShares(
        uint256 assetAmount,
        address receiver,
        bytes calldata depositData
    ) external override onlyLendingRouter setCurrentAccount(receiver) nonReentrant returns (uint256 sharesMinted) {
        // Cannot mint shares if the receiver has an active withdraw request
        if (_isWithdrawRequestPending(receiver)) revert CannotEnterPosition();
        ERC20(asset).safeTransferFrom(t_CurrentLendingRouter, address(this), assetAmount);
        sharesMinted = _mintSharesGivenAssets(assetAmount, depositData, receiver); // audit: unsanitized depositData

        t_AllowTransfer_To = t_CurrentLendingRouter;
        t_AllowTransfer_Amount = sharesMinted;
        // Transfer the shares to the lending router so it can supply collateral
        _transfer(receiver, t_CurrentLendingRouter, sharesMinted);
    }

    /// @dev Marked as virtual to allow for RewardManagerMixin to override
    function _mintSharesGivenAssets(uint256 assets, bytes memory depositData, address receiver) internal virtual returns (uint256 sharesMinted) { // audit
        if (assets == 0) return 0;

        // First accrue fees on the yield token
        _accrueFees();
        uint256 initialYieldTokenBalance = _yieldTokenBalance();
        _mintYieldTokens(assets, receiver, depositData); // audit
        uint256 yieldTokensMinted = _yieldTokenBalance() - initialYieldTokenBalance; // audit: can this be manipulated through reentrancy somehow???

        sharesMinted = (yieldTokensMinted * effectiveSupply()) / (initialYieldTokenBalance - feesAccrued() + VIRTUAL_YIELD_TOKENS); // audit: effectiveSupply can be manipulated to become greater than intended
        _mint(receiver, sharesMinted); // audit: reentrant
    }
```
3.
```solidity
     /// @dev By default we can use the withdraw request manager to stake the tokens
    function _mintYieldTokens(uint256 assets, address /* receiver */, bytes memory depositData) internal override virtual { // audit: can it be reentered to increase the yieldtoken balance somehow???
        ERC20(asset).approve(address(withdrawRequestManager), assets); // audit: reverts for USDT
        withdrawRequestManager.stakeTokens(address(asset), assets, depositData); // audit malicious data
    }
```
4.
```solidity
    function _initiateWithdraw(
        address account,
        uint256 yieldTokenAmount,
        uint256 sharesHeld,
        bytes memory data
    ) internal override virtual returns (uint256 requestId) {
        ERC20(yieldToken).approve(address(withdrawRequestManager), yieldTokenAmount);
        requestId = withdrawRequestManager.initiateWithdraw({ // audit: reentrancy here!!!!
            account: account, yieldTokenAmount: yieldTokenAmount, sharesAmount: sharesHeld, data: data
        });
    } // audit: does this affect the yield token balance somehow?
```


_NOTE_ The Uniswap multihop trade data should include a malicious swap middle pool to make the reentrancy callback itself even possible.

You can see the e2e PoC at the end of this report.


## Internal preconditions
None.


## Impact
Theft of other users' funds via stealing `YIELD_TOKEN`s from the pending ERC4626-variant `WithdrawalRequestManager` requests of other users.
```solidity
    /// @inheritdoc IYieldStrategy
    function initiateWithdraw(
        address account,
        uint256 sharesHeld,
        bytes calldata data
    ) external onlyLendingRouter setCurrentAccount(account) override returns (uint256 requestId) {
        requestId = _withdraw(account, sharesHeld, data); // audit: lacks nonreentrant modifier
    }

    /// @inheritdoc IYieldStrategy
    /// @dev We do not set the current account here because valuation is not done in this method. A
    /// native balance does not require a collateral check.
    function initiateWithdrawNative(
        bytes memory data // audit: lscks nonReentrant, so can reenter exactly here
    ) external override returns (uint256 requestId) { // audit: lacks the nonReentrant modifier
        requestId = _withdraw(msg.sender, balanceOf(msg.sender), data); // audit: unsanitized data
    }

    function _withdraw(address account, uint256 sharesHeld, bytes memory data) internal returns (uint256 requestId) {
        if (sharesHeld == 0) revert InsufficientSharesHeld();

        // Accrue fees before initiating a withdraw since it will change the effective supply
        _accrueFees();
        uint256 yieldTokenAmount = convertSharesToYieldToken(sharesHeld);
        requestId = _initiateWithdraw(account, yieldTokenAmount, sharesHeld, data);
        // Escrow the shares after the withdraw since it will change the effective supply
        // during reward claims when using the RewardManagerMixin.
        s_escrowedShares += sharesHeld;

    }
```


```solidity

    /// @inheritdoc IWithdrawRequestManager
    function setApprovedVault(address vault, bool isApproved) external override onlyOwner {
        isApprovedVault[vault] = isApproved;
        emit ApprovedVault(vault, isApproved);
    }

    /// @inheritdoc IWithdrawRequestManager
    function stakeTokens(
        address depositToken,
        uint256 amount,
        bytes calldata data // audit
    ) external override onlyApprovedVault returns (uint256 yieldTokensMinted) { // @audit: should actually be non reentrant I think
        uint256 initialYieldTokenBalance = ERC20(YIELD_TOKEN).balanceOf(address(this));
        ERC20(depositToken).safeTransferFrom(msg.sender, address(this), amount);
        (uint256 stakeTokenAmount, bytes memory stakeData) = _preStakingTrade(depositToken, amount, data); // audit: reenter and call initiateWithdraw from a diffferent vault (i.e., cross-contract reentrancy)
        _stakeTokens(stakeTokenAmount, stakeData);



        yieldTokensMinted = ERC20(YIELD_TOKEN).balanceOf(address(this)) - initialYieldTokenBalance; // audit: non-reliable due to reentrancy
        ERC20(YIELD_TOKEN).safeTransfer(msg.sender, yieldTokensMinted);
    }
    

    /// @inheritdoc IWithdrawRequestManager
    function initiateWithdraw(
        address account,
        uint256 yieldTokenAmount,
        uint256 sharesAmount,
        bytes calldata data
    ) external override onlyApprovedVault returns (uint256 requestId) {
        WithdrawRequest storage accountWithdraw = s_accountWithdrawRequest[msg.sender][account];
        if (accountWithdraw.requestId != 0) revert ExistingWithdrawRequest(msg.sender, account, accountWithdraw.requestId);

        // Receive the requested amount of yield tokens from the approved vault.
        ERC20(YIELD_TOKEN).safeTransferFrom(msg.sender, address(this), yieldTokenAmount); // audit: exchanging yieldtoken for the underlying assets

        requestId = _initiateWithdrawImpl(account, yieldTokenAmount, data); // audit: reentrancy here??? through forceWithdraw(...)???
        accountWithdraw.requestId = requestId;
        accountWithdraw.yieldTokenAmount = yieldTokenAmount.toUint120();
        accountWithdraw.sharesAmount = sharesAmount.toUint120();
        s_tokenizedWithdrawRequest[requestId] = TokenizedWithdrawRequest({
            totalYieldTokenAmount: yieldTokenAmount.toUint120(), // audit: may be outdated
            totalWithdraw: 0,
            finalized: false
        });

        emit InitiateWithdrawRequest(account, msg.sender, yieldTokenAmount, sharesAmount, requestId);
    }
```

The only swap path validations are ensuring the first and last tokens match expected values (tokenIn and deUSD in correct order) and a minimum length. This allows an attacker to insert their own malicious token and pool addresses mid-path. During the Uniswap swap, when execution reaches the attacker-controlled pool, the attacker’s token contract can execute arbitrary code in its transfer function. By coding this hook to reenter the Jigsaw protocol—specifically, calling HoldingManager.deposit—the attacker can deposit some new tokens before the swap completes.

```solidity
    function _exactInBatch(address from, Trade memory trade) private pure returns (bytes memory) {
        UniV3BatchData memory data = abi.decode(trade.exchangeData, (UniV3BatchData));

        // Validate path EXACT_IN = [sellToken, fee, ... buyToken]
        require(32 <= data.path.length);
        require(_toAddress(data.path, 0) == _getTokenAddress(trade.sellToken));
        require(_toAddress(data.path, data.path.length - 20) == _getTokenAddress(trade.buyToken));

        ISwapRouter.ExactInputParams memory params = ISwapRouter.ExactInputParams(
            data.path, from, trade.deadline, trade.amount, trade.limit
        );

        return abi.encodeWithSelector(ISwapRouter.exactInput.selector, params);
    }
```

```solidity
    function _getExecutionData(
        uint16 dexId,
        address from,
        Trade memory trade
    )
        internal
        pure
        returns (
            address spender,
            address target,
            uint256 msgValue,
            bytes memory executionCallData
        )
    {
        if (trade.buyToken == trade.sellToken) revert SellTokenEqualsBuyToken();

        if (DexId(dexId) == DexId.UNISWAP_V3) {
            return UniV3Adapter.getExecutionData(from, trade);
        } else if (DexId(dexId) == DexId.BALANCER_V2) {
```


```solidity

    /// @dev Initiates a withdraw request for the vault shares held by the account
    function _initiateWithdraw(
        address vault,
        address account,
        bytes calldata data
    ) internal returns (uint256 requestId) {
        uint256 sharesHeld = balanceOfCollateral(account, vault);
        if (sharesHeld == 0) revert InsufficientSharesHeld();
        return IYieldStrategy(vault).initiateWithdraw(account, sharesHeld, data); // audit
    }
```

## PoC

To run the real coded PoC you need to first modify the `AbstractStakingStrategy` and the `MorphoLendingRouter` contracts in such a way that all direct `asset.approve(...)` are replaced with either the custom safe `.checkApprove` or `.safeApprove` or `.forceApprove`.

In other words, you just need to fix this another USDT incompatibility error first.

```solidity
            p.createPoolAndMint(PoolCreator.CreateArgs({
                tokenA: IERC20(tokenIn),
                tokenAAmount: 1e6,
                tokenB: fakeToken,
                tokenBAmount: 1000e18,
                fee: poolFee,
                factory: IUniswapV3Factory(IPeripheryImmutableState(uniswapRouter).factory())
            }));
            vm.stopPrank();
        }

        HackCode code = new HackCode(manager, IERC20(tokenIn));

        // Since the holder's user cannot be a contract, the attacker has to resort to
        // https://eips.ethereum.org/EIPS/eip-7702 .
        // They can set a pointer in their EOA pointing to the code.
        // Since this EIP is not yet supported in Foundry, we'll emulate it with vm.etch:
        deal(tokenIn, user, 100e6, true);
        vm.etch(user, address(code).code);
        fakeToken.callme(user);

        bytes memory dataClaimInvest = abi.encode(
            amount * 99 / 100, // amountOutMinimum
            uint256(block.timestamp), // deadline
            abi.encodePacked(deUSD, poolFee, USDC, poolFee, tokenIn,
                // note how the control is temporary transferred to the attacker's token:
                poolFee, fakeToken, poolFee, tokenIn)
        );
```


You can see more tokens are minted that intended:

With the attack:
```bash
    │   │   │   │   └─ ← [Return] 50292400900908 [5.029e13]
    │   │   │   ├─ [23036] ERC4626Mock::transfer(StakingStrategy: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], 50092400904714 [5.009e13])
    │   │   │   │   ├─ emit Transfer(from: GenericERC4626WithdrawRequestManager: [0xF62849F9A0B5Bf2913b396098F7c7019b51A820a], to: StakingStrategy: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], value: 50092400904714 [5.009e13])
    │   │   │   │   ├─  storage changes:
    │   │   │   │   │   @ 0xb3024e141922907eb80bf787d622b0c592108908135c35e38e6ebb7d5636f1e4: 0x00000000000000000000000000000000000000000000000000002dbd9cb0cb2c → 0x0000000000000000000000000000000000000000000000000000002e90edc122
    │   │   │   │   │   @ 0x8e945654193bec28956c368b451931aae1dd2f910b3127995a9fc7169f7ea4d1: 0 → 0x00000000000000000000000000000000000000000000000000002d8f0bc30a0a
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ emit DeltaYieldToken(_delta: 50092400904714 [5.009e13])
```


Without the attack enabled:
```bash
    │   │   │   ├─ [548] ERC4626Mock::balanceOf(GenericERC4626WithdrawRequestManager: [0xF62849F9A0B5Bf2913b396098F7c7019b51A820a]) [staticcall]
    │   │   │   │   └─ ← [Return] 50192400902810 [5.019e13]
    │   │   │   ├─ [23036] ERC4626Mock::transfer(StakingStrategy: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], 49992400906616 [4.999e13])
    │   │   │   │   ├─ emit Transfer(from: GenericERC4626WithdrawRequestManager: [0xF62849F9A0B5Bf2913b396098F7c7019b51A820a], to: StakingStrategy: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], value: 49992400906616 [4.999e13])
    │   │   │   │   ├─  storage changes:
    │   │   │   │   │   @ 0xb3024e141922907eb80bf787d622b0c592108908135c35e38e6ebb7d5636f1e4: 0x00000000000000000000000000000000000000000000000000002da65439ea9a → 0x0000000000000000000000000000000000000000000000000000002e90edc122
    │   │   │   │   │   @ 0x8e945654193bec28956c368b451931aae1dd2f910b3127995a9fc7169f7ea4d1: 0 → 0x00000000000000000000000000000000000000000000000000002d77c34c2978
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ emit DeltaYieldToken(_delta: 49992400906616 [4.999e13])
```


The difference is **EXACTLY** the `99999998098` shares transferred during the reentrant swap callback via `initiateWithdraw` (i.e., `50092400904714-99999998098 = 4.99924009e13`.

You can see that more shares are minted than the deposit is really worth.

This can be maximized by targeting `forceWithdraw` to make an artificially earned delta even greater!

### See my Gist PoC here:

https://gist.github.com/c-plus-plus-equals-c-plus-one/500a3df82f34eb894db54a4e619fcfed

## Mitigation
The "before balance" state accounting hould be captured **after** the `_preStakingTrade` call:
```diff
    /// @inheritdoc IWithdrawRequestManager
    function stakeTokens(
        address depositToken,
        uint256 amount,
        bytes calldata data // audit
    ) external override onlyApprovedVault returns (uint256 yieldTokensMinted) { // @audit: should actually be non reentrant I think
-       uint256 initialYieldTokenBalance = ERC20(YIELD_TOKEN).balanceOf(address(this));
        ERC20(depositToken).safeTransferFrom(msg.sender, address(this), amount);
        (uint256 stakeTokenAmount, bytes memory stakeData) = _preStakingTrade(depositToken, amount, data); // audit: reenter and call initiateWithdraw from a diffferent vault (i.e., cross-contract reentrancy)
+       uint256 initialYieldTokenBalance = ERC20(YIELD_TOKEN).balanceOf(address(this));
        _stakeTokens(stakeTokenAmount, stakeData);



        yieldTokensMinted = ERC20(YIELD_TOKEN).balanceOf(address(this)) - initialYieldTokenBalance; // audit: REENTRANCY HERE??? 🪻🪻🪻
        ERC20(YIELD_TOKEN).safeTransfer(msg.sender, yieldTokensMinted);
    }
    
```

# Issue H-2: Double Withdrawal Attack via Reentrant Calls During Yield Token Redemption 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/285 

## Found by 
0xBoraichoT

### Summary

When a user redeems their collateral, they have two options:

1. **Initiate a withdrawal** via the **Withdraw Request Manager**, making them eligible to withdraw their funds after a predefined period.
2. **Swap their yield tokens for the asset token**, effectively exiting their position immediately.

However, only one of these two options should be allowed per position. If both are executed, a critical invariant is violated.

Currently, there is an exploit that allows a user to redeem their tokens and, during the swap process, re-enter the system to initiate a withdrawal request. This results in **two separate withdrawal claims** on the same position.

This behaviour **breaks the internal accounting of the contract** and can lead to a situation where earlier depositors are unable to withdraw their capital, as the system's liabilities exceed its actual assets.



### Root Cause

This function lacks a non-reentrant flag, making it vulnerable to possible reentrancy:

```solidity
function initiateWithdrawNative(
    bytes memory data
) external override returns (uint256 requestId) {
    requestId = _withdraw(msg.sender, balanceOf(msg.sender), data);
}
```


### Internal Pre-conditions

A user must just have a collateral position open.

### External Pre-conditions

None

### Attack Path

1. A malicious user has already deposited collateral and has an active position.
2. The malicious user then calls `exitPosition()` on the **Lending Router**.
3. The Lending Router transfers the user's collateral shares to the user and then invokes the `burnShare()` function on the **Yield Strategy** contract.
4. The `burnShares()` function which subsequently calls `_redeemShares()`, which swaps **Yield Tokens** for the underlying **Asset Tokens**.
5. During the token swap, the malicious user is able to **re-enter** the system and call the `initiateWithdraw()` function. This results in Yield Tokens being transferred to the **Withdraw Request Manager**, creating a withdrawal claim and Yield Tokens being directly transferred to a user. 


### Impact

The impact of this vulnerability is significant, as it is trivial to reproduce and can be exploited to block honest users from withdrawing their collateral from the system.

### PoC

_No response_

### Mitigation

**Add the `nonReentrant` modifier to the `initiateWithdrawNative` function.**


# Issue H-3: `migrateRewardPool` Fails Due to Incompatible Storage Design in `CurveConvexLib` 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/485 

## Found by 
Ledger\_Patrol, bretzel, tjonair, xiaoming90

### Summary

The [`migrateRewardPool`](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/rewards/AbstractRewardManager.sol#L44-L65) function in the `AbstractRewardManager` contract is designed to migrate rewards from an old Convex reward pool to a new one by updating internal storage, withdrawing from old reward pool and depositing into the new reward pool. This mechanism relies on writing to local storage slots (e.g., `_getRewardPoolSlot()`), via delegatecall from a yield strategy contract.

In practice, this fails because when `CurveConvex2Token` is deployed, it deploys `CurveConvexLib`, where reward pool address is immutable. The `CurveConvex2Token` stores the address of `CurveConvexLib` into another immutable variable.

Since the reward pool address is immutable in `CurveConvexLib`, whenever Lp token is minted, the `CurveConvex2Token` deposit them to the same reward pool even if reward pool is changed in reward manager. There is no migration possible in `CurveConvex2Token`. This breaks the core migration functionality, despite the function being exposed and annotated for use when the reward pool changes.

This violates the IRewardManager interface contract [NATSPEC](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/interfaces/IRewardManager.sol#L82-L86), which states that `migrateRewardPool` should be used both initially and when the reward pool changes — of which reward pool change can be accomplished properly in this case.


### Root Cause

None

### Internal Pre-conditions

None

### External Pre-conditions

Convex protocol can decide to deprecate an old pool and create a new one

### Attack Path

None

### Impact

Reward pool cannot be changed when convex migrates to a new reward pool

### PoC

_No response_

### Mitigation

Create a migration logic for `CurveConvex2Token` where reward pool can be migrated from one to another

# Issue H-4: Liquidations will revert if Bad debt is incurred 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/540 

## Found by 
Audinarey

### Summary

When a position is opened, [`MORPHO.supplyCollateral()`](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/routers/MorphoLendingRouter.sol#L163) is used to supply collateral to the MORPHO market as shown below

```sol
File: notional-v4/src/routers/MorphoLendingRouter.sol
150:     function _supplyCollateral(

//SNIP
161:         // We should receive shares in return
162:         ERC20(vault).approve(address(MORPHO), sharesReceived);
163:   @>    MORPHO.supplyCollateral(m, sharesReceived, onBehalf, ""); 
164:     }

```

### Root Cause

A close look at the [`MORPHO.supplyCollateral()`](https://github.com/morpho-org/morpho-blue/blob/b2279f2cbd55baa5a19892541e44b466b2801127/src/Morpho.sol#L303) implementation below shows that it is only the `position[id][onBehalf].collateral` that is incremented when collateral is supplied

```sol
File: morpho-blue/src/Morpho.sol
303:     function supplyCollateral(MarketParams memory marketParams, uint256 assets, address onBehalf, bytes calldata data)
304:         external
305:     {
306:         Id id = marketParams.id();
307:         require(market[id].lastUpdate != 0, ErrorsLib.MARKET_NOT_CREATED);
308:         require(assets != 0, ErrorsLib.ZERO_ASSETS);
309:         require(onBehalf != address(0), ErrorsLib.ZERO_ADDRESS);
310: 
311:         // Don't accrue interest because it's not required and it saves gas.
312: 
313:   @>    position[id][onBehalf].collateral += assets.toUint128(); // user's shares received

```

However during liquidation, when bad debt is incurred when the user's collateral is not enough to cover the debt, the bad debt is socialised in the particular market through [`market[id].totalSupplyAssets`](https://github.com/morpho-org/morpho-blue/blob/b2279f2cbd55baa5a19892541e44b466b2801127/src/Morpho.sol#L400)

```sol
File: morpho-blue/src/Morpho.sol
347:     function liquidate(
348:         MarketParams memory marketParams,
349:         address borrower,

////SNIP
390:         uint256 badDebtShares;
391:         uint256 badDebtAssets;
392:         if (position[id][borrower].collateral == 0) {
393:             badDebtShares = position[id][borrower].borrowShares;
394:             badDebtAssets = UtilsLib.min(
395:                 market[id].totalBorrowAssets,
396:                 badDebtShares.toAssetsUp(market[id].totalBorrowAssets, market[id].totalBorrowShares)
397:             );
398: 
399:             market[id].totalBorrowAssets -= badDebtAssets.toUint128();
400:     @>      market[id].totalSupplyAssets -= badDebtAssets.toUint128();
401:             market[id].totalBorrowShares -= badDebtShares.toUint128();
402:             position[id][borrower].borrowShares = 0;
403:         }
/////////
417:     }

```

The problem is that `supplyCollateral()` does not  increase the `market[id].totalSupplyAssets` thus when bad debt is incurred the function will attempt to reduce the `market[id].totalBorrowShares`  which is already zero thus causing the function to revert leaving the protocol with bad positions as the liquidation will not proceed.

Another problem that stems from the use of `MORPHO.supplyCollateral()` is that [interest is not accrued](https://github.com/morpho-org/morpho-blue/blob/b2279f2cbd55baa5a19892541e44b466b2801127/src/Morpho.sol#L181)

### Internal Pre-conditions

NIL

### External Pre-conditions

NIL

### Attack Path

See root cause section

### Impact

Liquidation can be blocked thus preventing users from liquidating unhealthy positions leaving the protocol insolvent.

### PoC

_No response_

### Mitigation

Consider using `MORPHO.supply()` instead of `MORPHO.supplyCollateral()`

# Issue H-5: `RewardManagerMixin.claimAccountRewards` lacks of necessary param check. 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/624 

## Found by 
Bluedragon, BugsBunny, HeckerTrieuTien, elolpuer, jasonxiale, patitonar

### Summary

In current implementation, `RewardManagerMixin.claimAccountRewards` function doesn't check `account` paramm, if the `MORPHO` is passed in as `account`, rewards will be transferred to `MORPHO`. Which isn't correct.


### Root Cause

1. As [RewardManagerMixin.claimAccountRewards](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/rewards/RewardManagerMixin.sol#L155-L177) shows, the function can be called by anyone, and the `account` param can be any address.
2. If the `msg.sender` isn't a lending router, the `sharesHeld` will be calculated by `balanceOf(account)` in [RewardManagerMixin.sol#L160-L164](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/rewards/RewardManagerMixin.sol#L160-L164)
```solidity
155     function claimAccountRewards(
156         address account,
157         uint256 sharesHeld
158     ) external nonReentrant returns (uint256[] memory rewards) {
159         uint256 effectiveSupplyBefore = effectiveSupply();
160         if (!ADDRESS_REGISTRY.isLendingRouter(msg.sender)) {
161             // If the caller is not a lending router we get the shares held in a
162             // native token account.
163             sharesHeld = balanceOf(account);
164         }
...
177     }
```

3. While a normal user calls `AbstractLendingRouter.enterPosition` to enter a vault, the vault will mint vaultToken in [AbstractLendingRouter.sol#L241](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/routers/AbstractLendingRouter.sol#L241), and the vaultToken will be transferred to MORPHO in [AbstractLendingRouter.sol#L244](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/routers/AbstractLendingRouter.sol#L244)
**So after `AbstractLendingRouter.enterPosition`, MORPHO's vaultToken balance will increase**. 

  So if `MORPHO` is passed to `RewardManagerMixin.claimAccountRewards`, it'll get reward tokens, which isn't correct.



### Internal Pre-conditions

None

### External Pre-conditions

None

### Attack Path

The malicious calls `AbstractLendingRouter.enterPosition` with MORPHO address as `account`.

Please apply the following patch in `tests/TestRewardManager.sol` and run
```bash
forge test --mc TestRewardManager --mt test_liquidate_withRewards -vv
[⠑] Compiling...
No files changed, compilation skipped

Ran 1 test for tests/TestRewardManager.sol:TestRewardManager
[PASS] test_liquidate_withRewards() (gas: 1519209)
Logs:
  y.balanceOf                             : 0
  y.balanceOf                             : 50000000000000000000000000000
  y                                       : 0x1d1499e622D69689cdf9004d05Ec547d650Ff211
  rewardToken.balanceOf(MorPho)           : 0
  emissionsToken.balanceOf(MorPho)        : 0
  rewardToken.balanceOf(liquidator)       : 0
  emissionsToken.balanceOf(liquidator)    : 0
  rewardToken.balanceOf(MorPho)           : 119999671233240000000000
  emissionsToken.balanceOf(MorPho)        : 1090909080000000000
  rewardToken.balanceOf(liquidator)       : 0
  emissionsToken.balanceOf(liquidator)    : 454545450000000000

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 532.76ms (11.83ms CPU time)

Ran 1 test suite in 628.60ms (532.76ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

As above output shows, MORPHO get rewards, which isn't correct.

```diff
diff --git a/notional-v4/tests/TestRewardManager.sol b/notional-v4/tests/TestRewardManager.sol
index dfdd463..286db0a 100644
--- a/notional-v4/tests/TestRewardManager.sol
+++ b/notional-v4/tests/TestRewardManager.sol
@@ -10,6 +10,7 @@ import "../src/withdraws/GenericERC20.sol";
 import {AbstractRewardManager, RewardPoolStorage} from "../src/rewards/AbstractRewardManager.sol";
 import {RewardManagerMixin} from "../src/rewards/RewardManagerMixin.sol";
 import {ConvexRewardManager} from "../src/rewards/ConvexRewardManager.sol";
+import {console2} from "forge-std/src/console2.sol";

 contract TestRewardManager is TestMorphoYieldStrategy {
     IRewardManager rm;
@@ -337,7 +338,10 @@ contract TestRewardManager is TestMorphoYieldStrategy {
         }
     }

-    function test_liquidate_withRewards(bool hasEmissions, bool hasRewards, bool isPartialLiquidation) public {
+    function test_liquidate_withRewards() public {
+        bool hasEmissions = true;
+        bool hasRewards  = true;
+        bool isPartialLiquidation = true;
         int256 originalPrice = o.latestAnswer();
         address liquidator = makeAddr("liquidator");
         if (hasEmissions) {
@@ -365,7 +369,9 @@ contract TestRewardManager is TestMorphoYieldStrategy {
         asset.approve(address(lendingRouter), type(uint256).max);
         uint256 sharesToLiquidate = isPartialLiquidation ? sharesBefore / 2 : sharesBefore;
         // This should trigger a claim on rewards
+        console2.log("y.balanceOf                             :", y.balanceOf(address(liquidator)));
         uint256 sharesToLiquidator = lendingRouter.liquidate(msg.sender, address(y), sharesToLiquidate, 0);
+        console2.log("y.balanceOf                             :", y.balanceOf(address(liquidator)));
         vm.stopPrank();

         if (hasRewards) assertApproxEqRel(rewardToken.balanceOf(msg.sender), expectedRewards, 0.0001e18, "Liquidated account shares");
@@ -380,21 +386,22 @@ contract TestRewardManager is TestMorphoYieldStrategy {
         if (hasEmissions) vm.warp(block.timestamp + 1 days);
         uint256 emissionsForLiquidator = 1e18 * sharesToLiquidator / y.totalSupply();

+        console2.log("y                                       :", address(y));
+        console2.log("rewardToken.balanceOf(MorPho)           :", rewardToken.balanceOf(address(0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb)));
+        console2.log("emissionsToken.balanceOf(MorPho)        :", emissionsToken.balanceOf(0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb));
+        console2.log("rewardToken.balanceOf(liquidator)       :", rewardToken.balanceOf(liquidator));
+        console2.log("emissionsToken.balanceOf(liquidator)    :", emissionsToken.balanceOf(liquidator));
         // This second parameter is ignored because we get the balanceOf from
         // the contract itself.
+        vm.startPrank(address(0xa1a2bbccddeeff));
+        RewardManagerMixin(address(rm)).claimAccountRewards(address(0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb), type(uint256).max);
+        vm.stopPrank();
         RewardManagerMixin(address(rm)).claimAccountRewards(liquidator, type(uint256).max);

-        uint256 expectedRewardsForLiquidator = hasRewards ? y.convertSharesToYieldToken(sharesToLiquidator) : 0;
-        if (hasRewards) assertApproxEqRel(rewardToken.balanceOf(liquidator), expectedRewardsForLiquidator, 0.0001e18, "Liquidator account rewards");
-        if (hasEmissions) assertApproxEqRel(emissionsToken.balanceOf(liquidator), emissionsForLiquidator, 0.0010e18, "Liquidator account emissions");
-
-        vm.prank(msg.sender);
-        lendingRouter.claimRewards(address(y));
-        uint256 sharesAfterUser = lendingRouter.balanceOfCollateral(msg.sender, address(y));
-        uint256 emissionsForUserAfter = 1e18 * sharesAfterUser / y.totalSupply();
-
-        if (hasRewards) assertApproxEqRel(rewardToken.balanceOf(msg.sender), expectedRewards + expectedRewards - expectedRewardsForLiquidator, 0.0001e18, "Liquidated account rewards");
-        if (hasEmissions) assertApproxEqRel(emissionsToken.balanceOf(msg.sender), emissionsForUser + emissionsForUserAfter, 0.0010e18, "Liquidated account emissions");
+        console2.log("rewardToken.balanceOf(MorPho)           :", rewardToken.balanceOf(address(0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb)));
+        console2.log("emissionsToken.balanceOf(MorPho)        :", emissionsToken.balanceOf(0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb));
+        console2.log("rewardToken.balanceOf(liquidator)       :", rewardToken.balanceOf(liquidator));
+        console2.log("emissionsToken.balanceOf(liquidator)    :", emissionsToken.balanceOf(liquidator));
     }

     function test_migrate_withRewards(bool hasEmissions, bool hasRewards) public {
@@ -761,4 +768,4 @@ contract TestRewardManager is TestMorphoYieldStrategy {
         assertEq(rewardToken.balanceOf(msg.sender), rewardsBefore1, "User account rewards no change");
     }

-}
\ No newline at end of file
+}
```


### Impact

Becase MORPHO will owns most of vaultToken, most of the rewards will be transferred to MORPHO, leading users get less rewards


### PoC

_No response_

### Mitigation

_No response_

# Issue H-6: Incorrect assumption that one (1) Pendle Standard Yield (SY) token is equal to one (1) Yield Token when computing the price in the oracle 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/689 

## Found by 
mstpr-brainbot, xiaoming90

### Summary

-

### Root Cause

- Incorrect assumption that one (1) Pendle Standard Yield (SY) token is equal to one (1) Yield Token when computing the price in the oracle

### Internal Pre-conditions

-

### External Pre-conditions

-

### Attack Path

When deploying the Pendle yield strategy, the deployer can choose to set the `useSyOracleRate_` to true or false. If `useSyOracleRate_` is set to true, the `PENDLE_ORACLE.getPtToSyRate()` function will be used to get the PT rate.

An example of such a setup is shown in the test script provided with the codebase, where the `useSyOracleRate_` setting is set to true in Line 115 below. 

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/tests/TestPTStrategyImpl.sol#L111

```solidity
File: TestPTStrategyImpl.sol
079:     function deployYieldStrategy() internal override {
080:         strategyName = "Pendle PT";
081:         address(deployCode("PendlePTLib.sol:PendlePTLib"));
082: 
083:         setMarketVariables();
084:         bool isSUSDe = tokenOut == address(sUSDe);
085: 
..SNIP..
106:         }
107: 
108:         w = ERC20(y.yieldToken());
109:         // NOTE: is tokenOut the right token to use here?
110:         (AggregatorV2V3Interface baseToUSDOracle, ) = TRADING_MODULE.priceOracles(address(tokenOut));
111:         PendlePTOracle pendleOracle = new PendlePTOracle(
112:             market,
113:             baseToUSDOracle,
114:             false,
115:             true, // @audit-info useSyOracleRate_
116:             15 minutes,
117:             "Pendle PT",
118:             address(0)
119:         );
120: 
121:         o = new MockOracle(pendleOracle.latestAnswer());
122:     }
```

When the `useSyOracleRate` is set to true, `PENDLE_ORACLE.getPtToSyRate()` function in Line 63 below will be used to get the PT rate. Note that `getPtToSyRate` will return how much Pendle's Standard Yield (SY) token per PT token.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/oracles/PendlePTOracle.sol#L63

```solidity
File: PendlePTOracle.sol
61:     function _getPTRate() internal view returns (int256) {
62:         uint256 ptRate = useSyOracleRate ?
63:             PENDLE_ORACLE.getPtToSyRate(pendleMarket, twapDuration) :
64:             PENDLE_ORACLE.getPtToAssetRate(pendleMarket, twapDuration);
65:         return ptRate.toInt();
66:     }
```

Note that Chainlink or other oracle providers do not provide a price feed directly for the Pendle SY token.

The root cause here is that the codebase incorrectly assumes the price of Pendle SY Token is always equivalent to the Yield Token. Thus, the protocol assumes that it is fine to use the price feed for the Yield Token for Pendle SY Token when computing the price. While this is generally true, it is not always the case that 1 SY == 1 Yield Token.

Not all SY contracts will burn one (1) SY share and return one (1) yield token back. Inspecting the Pendle's source code reveals that for some SY contracts, some redemptions will involve withdrawing/redemption from external staking protocol or performing swaps, which might suffer from slippage or fees.

Below is the Pendle's `SY.redeem` function showing that slippage might occur during the exchange, and thus 1 SY == 1 Yield Token does not always hold.

https://github.com/pendle-finance/pendle-core-v2-public/blob/46d13ce4168e8c5ad9e5641dd6380fea69e48490/contracts/interfaces/IStandardizedYield.sol#L87

```solidity
File: IStandardizedYield.sol
74:     /**
75:      * @notice redeems an amount of base tokens by burning some shares
76:      * @param receiver recipient address
77:      * @param amountSharesToRedeem amount of shares to be burned
78:      * @param tokenOut address of the base token to be redeemed
79:      * @param minTokenOut reverts if amount of base token redeemed is lower than this
80:      * @param burnFromInternalBalance if true, burns from balance of `address(this)`, otherwise burns from `msg.sender`
81:      * @return amountTokenOut amount of base tokens redeemed
82:      * @dev Emits a {Redeem} event
83:      *
84:      * Requirements:
85:      * - (`tokenOut`) must be a valid base token.
86:      */
87:     function redeem(
88:         address receiver,
89:         uint256 amountSharesToRedeem,
90:         address tokenOut,
91:         uint256 minTokenOut,
92:         bool burnFromInternalBalance
93:     ) external returns (uint256 amountTokenOut);
```

The following `_calculateBaseToQuote()` function will be used to compute how many asset tokens are worth per PT token. Assume that `useSyOracleRate_` is true.

- The `baseToUSD` will return how many asset tokens per Yield Token. Only the price feed of Yield token is supported by Chainlink and other oracle providers.
- The `_getPTRate` will return how many Pendle SY tokens per PT token

The following formula is used to compute how many asset tokens are worth per PT token:

```solidity
(asset tokens per PT) = (asset tokens per Yield Token) * (Pendle SY tokens per PT token)
```

This formula will only work if `Yield Token` is equivalent to `Pendle SY tokens`. However, as mentioned earlier, this is not true. In some cases, one Pendle SY token might be worth 0.95 Yield Token. In this case, the price returned will be inflated since it assumes that 1 SY == 1 Yield Token.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/oracles/PendlePTOracle.sol#L68

```solidity
File: PendlePTOracle.sol
68:     function _calculateBaseToQuote() internal view override returns (
69:         uint80 roundId,
70:         int256 answer,
71:         uint256 startedAt,
72:         uint256 updatedAt,
73:         uint80 answeredInRound
74:     ) {
75:         int256 baseToUSD;
76:         (
77:             roundId,
78:             baseToUSD,
79:             startedAt,
80:             updatedAt,
81:             answeredInRound
82:         ) = baseToUSDOracle.latestRoundData();
83:         require(baseToUSD > 0, "Chainlink Rate Error");
84:         // Overflow and div by zero not possible
85:         if (invertBase) baseToUSD = (baseToUSDDecimals * baseToUSDDecimals) / baseToUSD;
86: 
87:         int256 ptRate = _getPTRate();
88:         answer = (ptRate * baseToUSD) / baseToUSDDecimals;
89:     }
```

### Impact

High. Price computed will be inflated, leading collateral to be overvalued. As a result, users are allowed to borrow more than expected, affecting the protocol's solvency and increasing the risk of bad debt.

### PoC

_No response_

### Mitigation

_No response_

# Issue H-7: Hardcoded `useEth = true` in `remove_liquidity_one_coin` or `remove_liquidity` lead to stuck fund 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/691 

## Found by 
elolpuer, xiaoming90

### Summary

-

### Root Cause

-

### Internal Pre-conditions

-

### External Pre-conditions

-

### Attack Path

Assume the Curve V2 pool with two-token setup. The following are some of the Curve pools that fit into this example.

https://www.curve.finance/dex/ethereum/pools/teth/deposit/ (t/ETH)

- LP Token - https://etherscan.io/address/0x752ebeb79963cf0732e9c0fec72a49fd1defaeac

- Coin 0 - 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 (WETH)
- Coin 1 - 0xCdF7028ceAB81fA0C6971208e83fa7872994beE5 (T)

https://www.curve.finance/dex/ethereum/pools/cvxeth/deposit/ (cvxeth) 

- LP Token - https://etherscan.io/address/0xb576491f1e6e5e62f1d8f26062ee822b40b0e0d4
- Coin 0 - 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 (WETH)
- Coin 1 - 0x4e3FBD56CD56c3e72c1403e103b45Db9da5B9D2B (CVX)

Curve Pool's Coin 0 is WETH, and thus `ETH_INDEX` is set to 0 during deployment. I have checked the source code and confirmed that `ETH_INDEX` is 0. Readers can access the LP token's etherscan link above to view the source code and see that the `ETH_INDEX` is set to 0.

Note that the Yield Strategy vault's `TOKEN_1` is equal to Curve Pool's Coin 0 and is set to WETH.

Assume that the Yield Strategy (YS) vault's asset is WETH, and we will enter the pool on a single-sided basis, with all deposited assets being in WETH.

The `msgValue` at Line 237 will be zero as `TOKEN_1` is in WETH and not Native ETH (0x0). Thus, the condition `0 < msgValue` will be evaluated to `false`.

As a result, no native ETH will be forwarded to the Curve Pool. Instead, the Curve pool will pull the WETH from the YS vault later. In this case, the `use_eth` parameter will be set to `false`, which makes sense because we are entering the pool with WETH and not Native ETH.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/single-sided-lp/CurveConvex2Token.sol#L219

```solidity
File: CurveConvex2Token.sol
219:     function _enterPool(
220:         uint256[] memory _amounts, uint256 minPoolClaim, uint256 msgValue
221:     ) internal returns (uint256) {
..SNIP..
235:         } else if (CURVE_INTERFACE == CurveInterface.V2) {
236:             return ICurve2TokenPoolV2(CURVE_POOL).add_liquidity{value: msgValue}(
237:                 amounts, minPoolClaim, 0 < msgValue // use_eth = true if msgValue > 0
238:             );
239:         }
```

Note that `use_eth` is `false`. The condition at Line 959 will be `true` and the Curve Pool will pull WETH from YS vault. Then, in Line 962, it will unwrap the WETH to Native ETH balance and proceed with the rest of the calculations.

```solidity
File: v2 (0.3.1).py
920: @payable
921: @external
922: @nonreentrant('lock')
923: def add_liquidity(amounts: uint256[N_COINS], min_mint_amount: uint256,
924:                   use_eth: bool = False, receiver: address = msg.sender) -> uint256:
..SNIP..
954:     for i in range(N_COINS):
955:         if use_eth and i == ETH_INDEX:
956:             assert msg.value == amounts[i]  # dev: incorrect eth amount
957:         if amounts[i] > 0:
958:             coin: address = _coins[i]
959:             if (not use_eth) or (i != ETH_INDEX):
960:                 assert ERC20(coin).transferFrom(msg.sender, self, amounts[i])
961:                 if i == ETH_INDEX:
962:                     WETH(coin).withdraw(amounts[i])
963:             amountsp[i] = xp[i] - xp_old[i]
```

The problem here is that when exiting the pool either via `remove_liquidity_one_coin` or `remove_liquidity` function, the `useEth` parameter is hardcoded to `true`, as shown below.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/single-sided-lp/CurveConvex2Token.sol#L244

```solidity
File: CurveConvex2Token.sol
244:     function _exitPool(
245:         uint256 poolClaim, uint256[] memory _minAmounts, bool isSingleSided
246:     ) internal returns (uint256[] memory exitBalances) {
247:         if (isSingleSided) {
248:             exitBalances = new uint256[](_NUM_TOKENS);
..SNIP..
255:                 exitBalances[_PRIMARY_INDEX] = ICurve2TokenPoolV2(CURVE_POOL).remove_liquidity_one_coin(
256:                     // Last two parameters are useEth = true and receiver = this contract
257:                     poolClaim, _PRIMARY_INDEX, _minAmounts[_PRIMARY_INDEX], true, address(this)
258:                 );
259:             }
..SNIP..
279:                 // Remove liquidity on CurveV2 does not return the exit amounts so we have to measure
280:                 // them before and after.
281:                 ICurve2TokenPoolV2(CURVE_POOL).remove_liquidity(
282:                     // Last two parameters are useEth = true and receiver = this contract
283:                     poolClaim, minAmounts, true, address(this)
284:                 );
```

Since `use_eth` is true, in Line 1043 below, it will transfer Native ETH to YS when exiting the pool.

```solidity
File: v2 (0.3.1).py
1024: @external
1025: @nonreentrant('lock')
1026: def remove_liquidity(_amount: uint256, min_amounts: uint256[N_COINS],
1027:                      use_eth: bool = False, receiver: address = msg.sender):
..SNIP..
1037:     for i in range(N_COINS):
1038:         d_balance: uint256 = balances[i] * amount / total_supply
1039:         assert d_balance >= min_amounts[i]
1040:         self.balances[i] = balances[i] - d_balance
1041:         balances[i] = d_balance  # now it's the amounts going out
1042:         if use_eth and i == ETH_INDEX:
1043:             raw_call(receiver, b"", value=d_balance)
```

After exiting the pool, native ETH will reside in the YS vault, and the logic at Lines 205-211 will be executed. The first condition (`ASSET == address(WETH)`) will evaluate to `true` in Line 205 below. However, the subsequent conditions `TOKEN_1 == ETH_ADDRESS` and `TOKEN_2 == ETH_ADDRESS` both evaluate to `false` as neither `TOKEN_1` nor `TOKEN_2` is equal to `ETH_ADDRESS`(0x0). Note that `TOKEN_1` is equal to WETH and not Native ETH (0x0) in this scenario.

In this case, the Native ETH residing in the YS will not be wrapped back to WETH.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/single-sided-lp/CurveConvex2Token.sol#L205

```solidity
File: CurveConvex2Token.sol
198:     function unstakeAndExitPool(
199:         uint256 poolClaim, uint256[] memory _minAmounts, bool isSingleSided
200:     ) external returns (uint256[] memory exitBalances) {
201:         _unstakeLpTokens(poolClaim);
202: 
203:         exitBalances = _exitPool(poolClaim, _minAmounts, isSingleSided);
204: 
205:         if (ASSET == address(WETH)) {
206:             if (TOKEN_1 == ETH_ADDRESS) {
207:                 WETH.deposit{value: exitBalances[0]}();
208:             } else if (TOKEN_2 == ETH_ADDRESS) {
209:                 WETH.deposit{value: exitBalances[1]}();
210:             }
211:         }
212:     }
```

Note that if it is a single-side exit, the `_executeRedemptionTrades()` will not be executed. If it is a proportional exit, the `_executeRedemptionTrades()` function will be executed, the condition at Line 229 (`address(tokens[i]) == address(asset) -> (WETH == WETH) -> True`) will be `True` and the `finalPrimaryBalance` will be set to the exit balance, and the for-loop will continue without swapping any assets.

Either way, the Native ETH remains in the YS vault.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/single-sided-lp/AbstractSingleSidedLP.sol#L229

```solidity
File: AbstractSingleSidedLP.sol
223:     function _executeRedemptionTrades(
224:         ERC20[] memory tokens,
225:         uint256[] memory exitBalances,
226:         TradeParams[] memory redemptionTrades
227:     ) internal returns (uint256 finalPrimaryBalance) {
228:         for (uint256 i; i < exitBalances.length; i++) {
229:             if (address(tokens[i]) == address(asset)) {
230:                 finalPrimaryBalance += exitBalances[i];
231:                 continue;
232:             }
```

Since the rest of the protocol works only with WETH, but not Native ETH. Many of the protocol's logic will be broken.

One instance is that the `_burnShares` will check the before and after balance of WETH to compute how many WETH asset to return to the user. Since we only have Native ETH here, but not WETH, the `assetsWithdrawn` will be zero, and users will receive nothing in return during withdrawal/redemption.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/AbstractYieldStrategy.sol#L416

```solidity
File: AbstractYieldStrategy.sol
416:     function _burnShares(
417:         uint256 sharesToBurn,
418:         uint256 /* sharesHeld */,
419:         bytes memory redeemData,
420:         address sharesOwner
421:     ) internal virtual returns (uint256 assetsWithdrawn) {
422:         if (sharesToBurn == 0) return 0;
423:         bool isEscrowed = _isWithdrawRequestPending(sharesOwner);
424: 
425:         uint256 initialAssetBalance = TokenUtils.tokenBalance(asset);
426: 
427:         // First accrue fees on the yield token
428:         _accrueFees();
429:         _redeemShares(sharesToBurn, sharesOwner, isEscrowed, redeemData);
430:         if (isEscrowed) s_escrowedShares -= sharesToBurn;
431: 
432:         uint256 finalAssetBalance = TokenUtils.tokenBalance(asset);
433:         assetsWithdrawn = finalAssetBalance - initialAssetBalance;
```

### Impact

High. Loss of assets as shown in above scenario.


### PoC

_No response_

### Mitigation

For exiting pool code, update the code to only set `useEth` to `True` if `TOKEN_1` or `TOKEN_2` is equal to `ETH_ADDRESS`(0x0). Otherwise, `useEth` should be `False`.

In this scenario, `useEth` should be `false` when exiting the pool. If it is set to `false` in the first place, WETH will be forwarded to the YS vault, and everything will work as expected without error.

# Issue H-8: Malicious user can change the `TradeType` to steal funds from the vault or withdraw request manager 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/715 

## Found by 
mstpr-brainbot, xiaoming90

### Summary

-

### Root Cause

-

### Internal Pre-conditions

-

### External Pre-conditions

-

### Attack Path

**Instance 1 - Yield Strategy Vault**

Assume the following:

- The asset token of a yield strategy vault is WBTC
- The yield token of the vault is the LP token of a Curve Pool (DAI/WBTC)
- 1 WBTC is worth 100,000 DAI
- WBTC's decimals is 8. DAI's decimals is 18.

When redeeming the LP token, the vault received back 10,000 DAI and 1 WBTC. The intention of the `_executeRedemptionTrades` function is to swap all non-asset token (DAI in this example) to asset token (WBTC), as per the comment at Line 235 below.

Thus, the `t.tradeType` must always be set to `TradeType.EXACT_IN_SINGLE` so that exact amount of 10,000 DAI (10000e18) will be swapped for arbitrary amount of WBTC (asset token). In this case, it should receive 0.1 WBTC after swapping in 10,000 DAI.

> [!NOTE]
>
> The `t.minPurchaseAmount` should also be set to the maximum value possible, so that maximum allowance will be granted to the external DEX protocol to pull tokens from Notional. Refer to [here](https://github.com/sherlock-audit/2023-02-notional/blob/b33adfbe2d47ab602b4d626bb73ebd78bf7d5622/leveraged-vaults/contracts/trading/TradingUtils.sol#L118). In EXACT_OUT trades, approval will be given based on `trade.limit` value.

> [!NOTE]
>
> This attack will work for any trading adapters, as demonstrated in the scenario below. However, if one needs maximum flexibility and control in crafting the exploit, such as the ability to set `trade.amount` to an arbitrary value instead of being restricted to `exitBalances[i]` (10000e18), they can consider using the 0x's [ZeroExAdaptor](https://github.com/sherlock-audit/2023-02-notional/blob/main/leveraged-vaults/contracts/trading/adapters/ZeroExAdapter.sol) because it allows users to define arbitrary execution data, and there is no check against the execution data internally.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/single-sided-lp/AbstractSingleSidedLP.sol#L223

```solidity
File: AbstractSingleSidedLP.sol
222:     /// @dev Trades the amount of secondary tokens into the primary token after exiting a pool.
223:     function _executeRedemptionTrades(
224:         ERC20[] memory tokens,
225:         uint256[] memory exitBalances,
226:         TradeParams[] memory redemptionTrades
227:     ) internal returns (uint256 finalPrimaryBalance) {
228:         for (uint256 i; i < exitBalances.length; i++) {
229:             if (address(tokens[i]) == address(asset)) {
230:                 finalPrimaryBalance += exitBalances[i];
231:                 continue;
232:             }
233: 
234:             TradeParams memory t = redemptionTrades[i];
235:             // Always sell the entire exit balance to the primary token
236:             if (exitBalances[i] > 0) {
237:                 Trade memory trade = Trade({
238:                     tradeType: t.tradeType,
239:                     sellToken: address(tokens[i]), // @audit DAI
240:                     buyToken: address(asset), // @audit WBTC
241:                     amount: exitBalances[i], // @audit 10,000 DAI => 10000e18
242:                     limit: t.minPurchaseAmount,
243:                     deadline: block.timestamp,
244:                     exchangeData: t.exchangeData
245:                 });
246:                 (/* */, uint256 amountBought) = _executeTrade(trade, t.dexId);
247: 
248:                 finalPrimaryBalance += amountBought;
249:             }
250:         }
```

However, the issue here is that the `t.tradeType` can be set to any value by the caller or user. Thus, instead of setting it to `TradeType.EXACT_IN_SINGLE`, a malicious user can set it to `TradeType.EXACT_OUT_SINGLE`.

If the trade data is set to `TradeType.EXACT_OUT_SINGLE` as follows:

```solidity
Trade memory trade = Trade({
    tradeType: TradeType.EXACT_OUT_SINGLE,
    sellToken: DAI,
    buyToken: WBTC,
    amount: 10000e18, // 10,000 DAI
    limit: t.minPurchaseAmount,
    deadline: block.timestamp,
    exchangeData: t.exchangeData
});
```

This means that the trade will swap in an arbitrary amount of DAI for the exact amount of 10000e18 WBTC (= 1.0e14 WBTC token)

It is possible that there is an excess balance of DAI residing on the Yield Strategy vault due to several reasons (e.g., reward token happens to be DAI). In this case, the DAI tokens residing on the Yield Strategy vault will be swapped to 1.0e14 WBTC tokens.

To recap, if `TradeType.EXACT_IN_SINGLE` is used, the 0.1 WBTC will be received. If `TradeType.EXACT_OUT_SINGLE` is used, 1.0e14 WBTC will be received.

Thus, by changing the `TradeType`, the user could potentially obtain much more assets than expected and steal funds from the vault.

Following is an extract from the [Contest's README](https://github.com/sherlock-audit/2025-06-notional-exponent-xiaoming9090/tree/main?tab=readme-ov-file#q-please-discuss-any-design-choices-you-made). The protocol is designed to be extendable and intended to work with different pools and tokens. Thus, the above example is just one possible instance, and many other combinations are possible due to the different lending platforms, pool, tokens, reward tokens being supported by the protocol.

> Q: Please discuss any design choices you made.
>
> Notional Exponent is designed to be extendable to new yield strategies and opportunities as well as new lending platforms. 

**Instance 2 - Withdraw Request Manager**

The similar issue is also found in the `AbstractWithdrawRequestManager._preStakingTrade()` function, where the trade type can be arbitrarily defined by the caller in Line 277. The exploit method closely resembles the one described in the previous instance.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/withdraws/AbstractWithdrawRequestManager.sol#L268

```solidity
File: AbstractWithdrawRequestManager.sol
268:     function _preStakingTrade(address depositToken, uint256 depositAmount, bytes calldata data) internal returns (uint256 amountBought, bytes memory stakeData) {
269:         if (depositToken == STAKING_TOKEN) {
270:             amountBought = depositAmount;
271:             stakeData = data;
272:         } else {
273:             StakingTradeParams memory params = abi.decode(data, (StakingTradeParams));
274:             stakeData = params.stakeData;
275: 
276:             (/* */, amountBought) = _executeTrade(Trade({
277:                 tradeType: params.tradeType,
278:                 sellToken: depositToken,
279:                 buyToken: STAKING_TOKEN,
280:                 amount: depositAmount,
```

Assume that

- `depositToken` is not equal to the `STAKING_TOKEN`
- Yield Strategy vault's assets token is USDC. 
- `WITHDRAW_TOKEN` is USDC

After the WR is finalized, the withdraw token (USDC) will reside in WRM if someone calls `finalizeRequestManual`.

In this case, when a trade is executed, `sellToken=depositToken=USDC` and `buyToken=StakingToken`. Thus, malicious users can use the same exploit (setting trading type to EXACT_OUT) mentioned earlier to steal USDC funds on WRM to purchase more staking tokens than expected, which will, in turn, generate more yield tokens/collateral shares under their account.

### Impact

High. Malicious users can exploit this to steal funds from the vault.


### PoC

_No response_

### Mitigation

The fix is straightforward. Simply hardcoded the trade type to `TradeType.EXACT_IN_SINGLE` to prevent this exploit. This will ensure that an exact amount of tokens is swapped in exchange for an arbitrary amount of desired tokens, and not the other way round.

```diff
/// @dev Trades the amount of secondary tokens into the primary token after exiting a pool.
function _executeRedemptionTrades(
    ERC20[] memory tokens,
    uint256[] memory exitBalances,
    TradeParams[] memory redemptionTrades
) internal returns (uint256 finalPrimaryBalance) {
    for (uint256 i; i < exitBalances.length; i++) {
        if (address(tokens[i]) == address(asset)) {
            finalPrimaryBalance += exitBalances[i];
            continue;
        }

        TradeParams memory t = redemptionTrades[i];
        // Always sell the entire exit balance to the primary token
        if (exitBalances[i] > 0) {
            Trade memory trade = Trade({
-               tradeType: t.tradeType,
+               tradeType: TradeType.EXACT_IN_SINGLE,
                sellToken: address(tokens[i]),
                buyToken: address(asset),
                amount: exitBalances[i],
                limit: t.minPurchaseAmount,
                deadline: block.timestamp,
                exchangeData: t.exchangeData
            });
            (/* */, uint256 amountBought) = _executeTrade(trade, t.dexId);

            finalPrimaryBalance += amountBought;
        }
    }
}
```

```diff
function _preStakingTrade(address depositToken, uint256 depositAmount, bytes calldata data) internal returns (uint256 amountBought, bytes memory stakeData) {
    if (depositToken == STAKING_TOKEN) {
        amountBought = depositAmount;
        stakeData = data;
    } else {
        StakingTradeParams memory params = abi.decode(data, (StakingTradeParams));
        stakeData = params.stakeData;

        (/* */, amountBought) = _executeTrade(Trade({
-           tradeType: params.tradeType,
+           tradeType: TradeType.EXACT_IN_SINGLE,
            sellToken: depositToken,
            buyToken: STAKING_TOKEN,
            amount: depositAmount,
            exchangeData: params.exchangeData,
            limit: params.minPurchaseAmount,
            deadline: block.timestamp
        }), params.dexId);
    }
}
```

# Issue H-9: Stuck Withdrawal Due to Slashed/Dissolved Validator in Batched Redemptions 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/846 

## Found by 
0xc0ffEE, Atharv, Ledger\_Patrol, Ragnarok, Schnilch, X0sauce, aman, hgrano, xiaoming90

### Summary

When withdrawing assets through the `Dinero.sol` contract, the `PirexETH` protocol processes redemptions in 32 ETH batches, with each batch assigned to a specific validator's public key. A critical issue arises if a user's withdrawal spans multiple batches  and one of the associated validators becomes slashed or dissolved. In such a scenario, the entire withdrawal is blocked, preventing the user from accessing any of their funds, even those held by unslashed validators.


### Root Cause

A flawed check in `canFinalizeWithdrawRequest` causes it to reject the entire withdrawal if any associated validator is `slashed` or `dissolved`, even if others are valid.
```solidity
    function canFinalizeWithdrawRequest(uint256 requestId) public view returns (bool) {
        (uint256 initialBatchId, uint256 finalBatchId) = _decodeBatchIds(requestId);
        uint256 totalAssets;

        for (uint256 i = initialBatchId; i <= finalBatchId; i++) {
            IPirexETH.ValidatorStatus status = PirexETH.status(PirexETH.batchIdToValidator(i));

            if (status != IPirexETH.ValidatorStatus.Dissolved && status != IPirexETH.ValidatorStatus.Slashed) {
                // Can only finalize if all validators are dissolved or slashed
                return false;
            }

            totalAssets += upxETH.balanceOf(address(this), i);
        }
```
[Here](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/withdraws/Dinero.sol#L71-L87)

### Internal Pre-conditions

The user's withdrawal amount is a multiple of 32 ETH, or large enough to necessitate processing across multiple 32 ETH batches.


### External Pre-conditions

One or more validators responsible for a portion of the user's batched withdrawal are subjected to slashing or become dissolved.


### Attack Path

1. A user initiates a withdrawal of `64` ETH from the `Dinero.sol` contract.
2. `Dinero.sol` subsequently calls `PirexETH.initiateRedemption`. `PirexETH` processes this withdrawal by splitting the `64` ETH into `2` 32 ETH batches. Each batch is assigned to a unique validator public key  `validatorPubKey1` for batch 1, `validatorPubKey2` for batch 2.
3. At some point after the initiation, validators assigned to a  batch 2 `validatorPubKey2` gets slashed or dissolved.
4. The user then attempts to call `finalizeWithdraw` to claim their assets.
5. During the `finalizeWithdraw` process, `Dinero.sol` invokes `canFinalizeWithdrawRequest`  to ascertain if the withdrawal can be completed.
6. The `canFinalizeWithdrawRequest` function iterates through the statuses of all validators associated with the withdrawal request, including `validatorPubKey1` and `validatorPubKey2`.
7. Because `validatorPubKey2` is now marked as `Slashed` or `Dissolved`, the `canFinalizeWithdrawRequest` function returns `false`, causing the entire withdrawal transaction to revert. This occurs despite the fact that the assets associated with `validatorPubKey1` are healthy and could otherwise be safely withdrawn.


### Impact

Users are indefinitely blocked from withdrawing if any validator in their batched redemption is slashed or dissolved , which is not correct design choice



### PoC

NI

### Mitigation

The Best approach for `Dinero` would be to allow admin or trusted users that they could withdraw assets from `PirexETH` for specific batchId, in this way the slashed/dissolved validator batchID assets will remain stuck but the remaining assets can be withdrawn


# Issue H-10: Migration of the reward pool will render the strategy contract useless 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/885 

## Found by 
mstpr-brainbot

### Summary

The upgrade admin can migrate the Convex reward pool if a new Convex "pid" is set for the LP token. However, when doing so, it cannot change the immutable "pid" in the strategy bytecode; instead, it withdraws from the old "pid" and deposits into the new one.

### Root Cause

In Convex, when a reward pool needs to be retired, a new "pid" with a new reward pool is created, because two reward pools cannot point to the same "pid". Migration handles this correctly by withdrawing from the old "pid" and depositing into the new "pid" which, after migration, effectively changes the yield token.

However, `yieldToken` is immutable in the yield strategy, which means that all deposits and withdrawals will still refer to the previous rewardPool/yieldToken. Since the entire LP is now staked in the new "pid", this results in a different token.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/rewards/ConvexRewardManager.sol#L17-L30

### Internal Pre-conditions

1. Notional migrates from the old pid to new pid

### External Pre-conditions

1. Convex migrates the curve lp token pid to a different pid

### Attack Path

1. See the migration transaction since the strategy will be not reachable by any user due to yield token pointing to a previous yield token which is no longer hold by strategy, attacker can borrow the maximum amount possible 

### Impact

Strategy is completely blocked for any user action. Deposits, withdraws, borrows and liquidations are not possible.

### PoC

_No response_

### Mitigation

When migrating change the "pid" as well or never migrate to a different pid instead let users know they manually need to migrate 

# Issue M-1: Curve gauge interface mismatch 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/74 

## Found by 
KungFuPanda

## Root cause
The Curve Gauge Liquidity interface is not compatible with the V6, even though the hardcoded address in the codebase points out **EXACTLY** at the V6 implementation's version.

- https://etherscan.io/address/0x330Cfd12e0E97B0aDF46158D2A81E8Bd2985c6cB#code

I've noticed that you're calling deposit and withdraw with only 1 parameter, yet the v6 gauge requires a claim boolean parameter.

There is an interface incompatibility issue, which will cause consequent reverts.

It was not caught in the tests though because the first condition of the `if/else` clause always shadowed this path.


## Vulnerability details

- https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/single-sided-lp/CurveConvex2Token.sol#L290C1-L309C1

## Impact
DoS, inability to use the curve gauge and stake/unstake LP tokens in this settup variant basically:
```solidity

    function _unstakeLpTokens(uint256 poolClaim) internal {
        if (CONVEX_REWARD_POOL != address(0)) {
            bool success = IConvexRewardPool(CONVEX_REWARD_POOL).withdrawAndUnwrap(poolClaim, false);
            require(success);
        } else {
            ICurveGauge(CURVE_GAUGE).withdraw(poolClaim);
        }
    }

    function _stakeLpTokens(uint256 lpTokens) internal {
        if (CONVEX_BOOSTER != address(0)) {
            bool success = IConvexBooster(CONVEX_BOOSTER).deposit(CONVEX_POOL_ID, lpTokens, true);
            require(success);
        } else {
            ICurveGauge(CURVE_GAUGE).deposit(lpTokens);
        }
    }
```

## Mitigation
Fix the interface and calldata parameters to ensure the arguments are compatible.

# Issue M-2: Issue in secondary reward emission calculation leads to loss of yield 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/169 

## Found by 
heavyw8t

### Summary

When the user claims their rewards, they also receive additional rewards through a fixed yearly emission rate. The additional reward is first calculated by share and then later multiplied by the number of shares a user has. There are multiple scenarios in which the reward per share for a certain time interval can be less than 1, leading to the reward being rounded to 0.  The user will receive no rewards, even though they would receive significant rewards if their reward per share were multiplied by their share amount.


### Root Cause

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/rewards/AbstractRewardManager.sol#L287-L314

As the secondary reward is calculated per single share and only for a certain (potentially minimal) time interval, there are many possible cases in which the dividing term can be larger than the divided term, such as:
- Reward token with 6 decimals, for example `USDC` (most likely)
- Low yearly emission rate
- A High amount of shares/funds in the pool
- Little time has passed since the last claim
This causes the reward per share to be smaller than 1, which then gets rounded to 0 by default in Solidity. Since the multiplication with the number of shares happens later, users will receive no rewards.

### Internal Pre-conditions

Either one or both of these conditions:
- Reward token with 6 decimals, for example `USDC` (most likely)
- Very Low yearly emission rate

### External Pre-conditions

Either one or both of these conditions:

- High amount of shares/funds in the pool
- Little time has passed since the last claim

Only the internal or external conditions on their own can also be enough, e.g., if the reward token has 6 decimals, even with smaller deposits and a larger claim time window, the issue can still occur


### Attack Path

- User deposits 100000e6 `USDC`
- The user borrows `USDC` 100000e6 `USDC` and deposits everything into a SingleSidedLP pool
- The user receives 200000e18 `yieldTokens` as yield tokens use 18 decimal precision
- The initial depositor receives the following amount of shares:
$` sharesMinted = (yieldTokensMinted * effectiveSupply()) / (initialYieldTokenBalance - feesAccrued() + VirtualYieldTokens) `$
Which, in this case, equates to:
$` 2e29 = (200000e18 * 1e6()) / (0 - 0 + 1)`$

- The user claims their rewards after a week in the protocol through `claimRewards`
- The secondary rewards are calculated using `_getAccumulatedRewardViaEmissionRate`
- Let's set the `emissionRatePerYear` to an arbitrary 100000e6 tokens
The rewards per share are now calculated as follows: $`(604800*1e18*1e11)/(3,154e7*(2e29 + 1e6)) = 0.0096`$
This value will then be rounded to 0 by Solidity, resulting in the user receiving no secondary rewards. The more users deposit in the pool, the larger the problem becomes as the secondary rewards are divided by a larger and larger effective supply.

### Impact

High

Loss of yield for the user

In the example calculated in the attack path, the user would need to wait two years to claim their reward. If other users were to join the pool, this could get even worse, for example, 20 years if the pool has 1 million `USDC` in total.

### PoC

See Attack path

### Mitigation

Increase the precision of the values used in the calculation first and scale them back down after multiplying with the number of shares further down the line


# Issue M-3: Incorrect `tokensClaimed` calculation in `EthenaCooldownHolder::_finalizeCooldown()` blocks withdrawals 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/263 

## Found by 
0xDeoGratias, 0xc0ffEE, 0xpiken, 0xzey, Atharv, Cybrid, KungFuPanda, Ragnarok, Schnilch, X0sauce, almurhasan, boredpukar, bretzel, elolpuer, hgrano, holtzzx, kangaroo, patitonar, pseudoArtist, touristS, xiaoming90

### Summary

Users are unable to withdraw tokens from the `EthenaWithdrawRequestManager` contract when initiating a withdrawal while `sUSDe.cooldownDuration()` is set to `0`, due to flawed logic in the `EthenaCooldownHolder::_finalizeCooldown()` function.

### Root Cause

When a user initiates a withdrawal request via the `EthenaWithdrawRequestManager` contract, it internally calls `EthenaCooldownHolder::_startCooldown()`:

[EthenaCooldownHolder::_startCooldown()](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/withdraws/Ethena.sol#L16) function:
```solidity
function _startCooldown(uint256 cooldownBalance) internal override {
      uint24 duration = sUSDe.cooldownDuration();
      if (duration == 0) {
          // If the cooldown duration is set to zero, can redeem immediately
=>        sUSDe.redeem(cooldownBalance, address(this), address(this));
      } else {
         ...
      }
  }
```

If `cooldownDuration` is `0`, the `sUSDe` is immediately redeemed for `USDe`, and the `USDe` tokens are transferred to the `EthenaCooldownHolder` contract. Later, when the user finalizes their withdrawal, `EthenaCooldownHolder::_finalizeCooldown()` is called:

[EthenaCooldownHolder::_finalizeCooldown()](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/withdraws/Ethena.sol#L30) function:
```solidity
function _finalizeCooldown() internal override returns (uint256 tokensClaimed, bool finalized) {
    uint24 duration = sUSDe.cooldownDuration();
    IsUSDe.UserCooldown memory userCooldown = sUSDe.cooldowns(address(this));

    if (block.timestamp < userCooldown.cooldownEnd && 0 < duration) {
        // Cooldown has not completed, return a false for finalized
        return (0, false);
    }

    uint256 balanceBefore = USDe.balanceOf(address(this));
    if (0 < userCooldown.cooldownEnd) sUSDe.unstake(address(this));
    uint256 balanceAfter = USDe.balanceOf(address(this));

=>  tokensClaimed = balanceAfter - balanceBefore;
    USDe.transfer(manager, tokensClaimed);
    finalized = true;
}
```

Since the `USDe` has already been withdrawn to the holder contract at the time the withdrawal request is initiated, `balanceBefore` is equal to `balanceAfter`. As a result, `tokensClaimed` is incorrectly calculated as 0, preventing users from claiming any tokens from their withdrawal request.

### Impact

Users are unable to claim any tokens from their withdrawal requests if they were initiated when `sUSDe.cooldownDuration()` was `0`.

### Mitigation

Track the balance change when initiating a withdrawal request while `sUSDe.cooldownDuration()` is set to 0, and use this state to determine the balance change when finalizing the withdrawal request.

# Issue M-4: Minting yield tokens single sided can be impossible if CURVE_V2 dexId is used on redemptions 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/320 

## Found by 
mstpr-brainbot

### Summary

In single-sided yield strategies, both underlying tokens of the pool have infinite allowance set on the pool contract. When a user chooses to withdraw, they can withdraw with both tokens and then sell the underlying tokens for the "asset".

If the user selects **CURVE\_V2** and sets the swap pool to be the **same pool** that the strategy is currently LP'ing into, then the `TRADING_MODULE` will **revoke the token allowances (set to 0)** for security. This breaks the strategy, as it will no longer have the required token allowance to deposit into the yield strategy, effectively making deposits impossible.


### Root Cause

Let's go through an example with explanations. Assume the yield strategy's yield token is the Convex crvUSD-USDC LP token and the asset is USDC.

First, when the strategy is deployed, both USDC and crvUSD will be infinitely approved to the pool to mint LP tokens:
[https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/single-sided-lp/CurveConvex2Token.sol#L169-L178](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/single-sided-lp/CurveConvex2Token.sol#L169-L178)

Now, say Alice comes and wants to withdraw her shares double-sided to crvUSD and USDC and then sells the USDC for crvUSD in the same pool:
[https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/single-sided-lp/AbstractSingleSidedLP.sol#L163-L178](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/single-sided-lp/AbstractSingleSidedLP.sol#L163-L178)

As we can see, the tokens received will be sold to the "asset" token, and since the asset is USDC, the USDC withdrawn from the LP will be skipped and only crvUSD will be sold to USDC:
[https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/single-sided-lp/AbstractSingleSidedLP.sol#L223-L251](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/single-sided-lp/AbstractSingleSidedLP.sol#L223-L251)

However, as we can see above, `dexId` is not forced. The user can pick CURVE\_V2 and set the pool to be the same pool the strategy is depositing into:
[https://github.com/notional-finance/leveraged-vaults/blob/7e0abc3e118db0abb20c7521c6f53f1762fdf562/contracts/trading/adapters/CurveV2Adapter.sol#L42-L63](https://github.com/notional-finance/leveraged-vaults/blob/7e0abc3e118db0abb20c7521c6f53f1762fdf562/contracts/trading/adapters/CurveV2Adapter.sol#L42-L63)

If that's the case, crvUSD will be swapped to USDC in the same pool, and after the `TRADING_MODULE` finishes swapping, it revokes the allowance of the `sellToken`, which in this case is USDC:
[https://github.com/notional-finance/leveraged-vaults/blob/7e0abc3e118db0abb20c7521c6f53f1762fdf562/contracts/trading/TradingUtils.sol#L54-L57](https://github.com/notional-finance/leveraged-vaults/blob/7e0abc3e118db0abb20c7521c6f53f1762fdf562/contracts/trading/TradingUtils.sol#L54-L57)

Now, the user will receive their USDC and a successful withdrawal but what happened is that the yield strategy now has **zero** allowance on the yield token (the Curve pool), which means **no user can deposit into the strategy anymore**. It’s permanently blocked because the strategy is always expected to have infinite allowance, but now has none.


### Internal Pre-conditions

1. "asset" token is one of the curve lp tokens (very possible)


### External Pre-conditions

None needed

### Attack Path

1. Exit position double sided with redemption trade using the same curve pool

### Impact

Strategy deposits are permanently blocked due to lack of allowance for "asset" token to pool. 

### PoC

_No response_

### Mitigation

Do not allow CURVE_V2 if "asset" token trade.pool is the same. For CURVE_V2 multiple swaps it could be a problem to check each pool but I guess thats not the case since the router has the one doing the swaps not the strategy. 

# Issue M-5: OETH Strategy Broken as Rebasing Not Enabled 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/538 

## Found by 
h2134, seeques, talfao

### Summary

The Yield Strategy using Origin ETH is not functioning as intended due to a design flaw. It utilizes Origin ETH with rebasing turned off. Since rebasing is required to receive ETH yield rewards, the strategy fails to generate yield. The Notional Protocol team confirmed that the protocol should ideally migrate to Wrapped OETH to enable proper yield accrual.

### Root Cause

The issue lies in the design, specifically in [`Origin.sol:_stakeTokens{...}`](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/withdraws/Origin.sol#L25), where the Origin Vault is used to exchange WETH for OETH. However, the OETH used has rebasing disabled, which prevents it from generating yield. According to the Origin Protocol documentation:

> *By default, OUSD, OETH, OS and Super OETH held on smart contracts will not participate in the rebasing nature of the token and will forfeit any yield unless the smart contract explicitly opts in.* [ref](https://docs.originprotocol.com/yield-bearing-tokens/core-concepts/rebasing-and-smart-contracts)

### Internal Pre-conditions

None

### External Pre-conditions

None

### Attack Path

This is a design flaw and has been confirmed by the protocol team.

### Impact

Core functionality is broken — the strategy fails to generate yield. This can result in a high risk of liquidation since the debt will increase while no yield offsets it (especially if used within Morpho).

### PoC

Not required. The issue is confirmed in the OETH documentation and can also be verified in the OETH source code.

### Mitigation

The simplest mitigation is to migrate to Wrapped OETH, which supports yield accrual.


# Issue M-6: DoS might happen to `DineroWithdrawRequestManager#_initiateWithdrawImpl()` due to overflow on `++s_batchNonce` 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/580 

## Found by 
0xpiken, HeckerTrieuTien, Ledger\_Patrol, Ragnarok, X0sauce, heavyw8t, y4y

### Summary

When `DineroWithdrawRequestManager#initiateWithdraw()` is called to initiate WETH withdrawal, [`DineroWithdrawRequestManager#_initiateWithdrawImpl()`](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/withdraws/Dinero.sol#L17-L39) will be executed to initiate a redemption from `PirexETH`:
```solidity
    function _initiateWithdrawImpl(
        address /* account */,
        uint256 amountToWithdraw,
        bytes calldata /* data */
    ) override internal returns (uint256 requestId) {
        if (YIELD_TOKEN == address(apxETH)) {
            // First redeem the apxETH to pxETH before we initiate the redemption
            amountToWithdraw = apxETH.redeem(amountToWithdraw, address(this), address(this));
        }

        uint256 initialBatchId = PirexETH.batchId();
        pxETH.approve(address(PirexETH), amountToWithdraw);
        // TODO: what do we put for should trigger validator exit?
        PirexETH.initiateRedemption(amountToWithdraw, address(this), false);
        uint256 finalBatchId = PirexETH.batchId();
@>      uint256 nonce = ++s_batchNonce;

        // May require multiple batches to complete the redemption
        require(initialBatchId < MAX_BATCH_ID);
        require(finalBatchId < MAX_BATCH_ID);
        // Initial and final batch ids may overlap between requests so the nonce is used to ensure uniqueness
        return nonce << 240 | initialBatchId << 120 | finalBatchId;
    }
```
The returned `requestId` is composed by three variables: `nonce`, `initialBatchId`, and `finalBatchId`.
`nonce` is calculated as below:
```solidity
        uint256 nonce = ++s_batchNonce;
```
However, `s_batchNonce` is a `uint16` variable. Once its value reaches `65535`, then `++s_batchNonce` will revert the whole `initiateWithdraw()` function, resulting no one can withdraw WETH though `DineroWithdrawRequestManager`. Anyone asset deposited through `DineroWithdrawRequestManager` will be locked forever.

### Root Cause

The capacity of `s_batchNonce` is too small.

### Internal Pre-conditions

_No response_

### External Pre-conditions

_No response_

### Attack Path

Malicious attacker can call  `DineroWithdrawRequestManager#stakeTokens()` and `DineroWithdrawRequestManager#initiateWithdraw()` repeatedly with different accounts through an approved vault  to quickly increase `s_batchNonce` to `65535`. 

### Impact

Once `s_batchNonce` reaches `65535`, `DineroWithdrawRequestManager#initiateWithdraw()` call will always revert and no any WETH can be withdrawn from `DineroWithdrawRequestManager`.

### PoC

_No response_

### Mitigation

The reason that defining `s_batchNonce` as `uint16` is  that `s_batchNonce` will be used together with two `uint120` variables to make a `uint256` variable:
```solidity
        return nonce << 240 | initialBatchId << 120 | finalBatchId;
```
Since `PirexETH.batchId()` will increase one time only every 32 ether redemption, it is unnecessary to record two batchIds in `requestId`. `requestId` can be redesigned as below:
```code
|255------136|135---------16|15---------0|
|s_batchNonce|initialBatchId|deltaBatchId|
``` 
Where `uint16 deltaBatchId = finalBatchId - initialBatchId`
Then `s_batchNonce` can be defined as a `uint120` variable.

# Issue M-7: Incorrect asset matching for ETH/WETH leads to potential DoS of exitPosition in CurveConvexStrategy 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/581 

## Found by 
0xDeoGratias, Cybrid, HeckerTrieuTien, auditgpt, bretzel, touristS

### Summary

When redeeming shares in `CurveConvexStrategy`, the `_executeRedemptionTrades` function is intended to skip swap logic for the primary token. 
However, when the strategy's asset is WETH and one of the exit tokens is ETH_ADDRESS, the comparison `(address(tokens[i]) == address(asset))` fails because ETH and WETH have different addresses. This leads to an unnecessary swap attempt using invalid trade parameters, potentially causing a denial of service (DoS).

---

### Root Cause

In the CurveConvex strategy, when redeeming shares (via `exitPosition` or `initiateWithdraw`), LP tokens are first unstaked and exited from the pool using `unstakeAndExitPool()`.
If one of the pool tokens is native ETH and the strategy’s `ASSET` is WETH, the strategy wraps ETH into WETH.
https://github.com/sherlock-audit/2025-06-notional-exponent-sylvarithos/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/single-sided-lp/CurveConvex2Token.sol#L205
```solidity
function unstakeAndExitPool(
    uint256 poolClaim, uint256[] memory _minAmounts, bool isSingleSided
) external returns (uint256[] memory exitBalances) {
    _unstakeLpTokens(poolClaim);

    exitBalances = _exitPool(poolClaim, _minAmounts, isSingleSided);

205  if (ASSET == address(WETH)) {
        if (TOKEN_1 == ETH_ADDRESS) {
            WETH.deposit{value: exitBalances[0]}();
        } else if (TOKEN_2 == ETH_ADDRESS) {
            WETH.deposit{value: exitBalances[1]}();
        }
    }
}
```

When not singlesided trade, it executes trade to convert to primary token.
https://github.com/sherlock-audit/2025-06-notional-exponent-sylvarithos/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/single-sided-lp/AbstractSingleSidedLP.sol#L176
```solidity
function _redeemShares(
    uint256 sharesToRedeem,
    address sharesOwner,
    bool isEscrowed,
    bytes memory redeemData
) internal override {
    RedeemParams memory params = abi.decode(redeemData, (RedeemParams));
    ...
    if (!isSingleSided) {
        // If not a single sided trade, will execute trades back to the primary token on
        // external exchanges. This method will execute EXACT_IN trades to ensure that
        // all of the balance in the other tokens is sold for primary.
        // Redemption trades are not automatically enabled on vaults since the trading module
        // requires explicit permission for every token that can be sold by an address.
        _executeRedemptionTrades(tokens, exitBalances, params.redemptionTrades);
    }
}
```

However, in `_executeRedemptionTrades()`, when iterating over the `tokens` array to check if a token matches `asset` (to skip trading), it uses a strict equality check:
https://github.com/sherlock-audit/2025-06-notional-exponent-sylvarithos/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/single-sided-lp/AbstractSingleSidedLP.sol#L229
```solidity
function _executeRedemptionTrades(
    ERC20[] memory tokens,
    uint256[] memory exitBalances,
    TradeParams[] memory redemptionTrades
) internal returns (uint256 finalPrimaryBalance) {
    for (uint256 i; i < exitBalances.length; i++) {
229     if (address(tokens[i]) == address(asset)) {
            finalPrimaryBalance += exitBalances[i];
            continue;
        }

        TradeParams memory t = redemptionTrades[i];
        // Always sell the entire exit balance to the primary token
        if (exitBalances[i] > 0) {
            Trade memory trade = Trade({
                tradeType: t.tradeType,
                sellToken: address(tokens[i]),
                buyToken: address(asset),
                amount: exitBalances[i],
                limit: t.minPurchaseAmount,
                deadline: block.timestamp,
                exchangeData: t.exchangeData
            });
            (/* */, uint256 amountBought) = _executeTrade(trade, t.dexId);

            finalPrimaryBalance += amountBought;
        }
    }
}
```

This fails when `tokens[i]` is ETH (i.e., `ETH_ADDRESS`) and `asset` is WETH, even though ETH was already converted into WETH during the exit step.
This leads to an unnecessary swap attempt using invalid trade parameters, potentially causing a denial of service (DoS).

---

### Internal Pre-conditions

- The strategy asset is set to WETH.
- The LP token pool contains ETH as one of its underlying tokens.

---

### Impact

A revert in `_executeTrade()` halts redemptions, locking user funds in the vault. This can block all users from exiting if their share includes ETH from the pool.

---

### Mitigation

Should compare with primary_index.

```solidity
function _executeRedemptionTrades(
    ERC20[] memory tokens,
    uint256[] memory exitBalances,
    TradeParams[] memory redemptionTrades
) internal returns (uint256 finalPrimaryBalance) {
    for (uint256 i; i < exitBalances.length; i++) {
-       if (address(tokens[i]) == address(asset)) {
+       if (address(tokens[i]) == PRIMARY_INDEX()) {
            finalPrimaryBalance += exitBalances[i];
            continue;
        }
	...
}
```

# Issue M-8: Some transient variables might break the invariants. 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/619 

## Found by 
jamesdean, jasonxiale, xiaoming90

### Summary

Quoting from the main page:
>After each action via a lending router (enterPosition, exitPosition, migratePosition, liquidate, initiateWithdraw, forceWithdraw, claimRewards, healthFactor), any transient variables on the vault are cleared and cannot be re-used in another call back to the lending router in the same transaction.

transient variables `t_AllowTransfer_To` and `t_AllowTransfer_Amount` might break the invariants in some case.



### Root Cause

I'll take [AbstractLendingRouter.exitPosition](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/routers/AbstractLendingRouter.sol#L108-L130) as an example
1. `_redeemShares` will be called in [AbstractLendingRouter.sol#L123](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/routers/AbstractLendingRouter.sol#L122)
2. In [AbstractLendingRouter._redeemShares](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/routers/AbstractLendingRouter.sol#L248C14-L269), [IYieldStrategy(vault).allowTransfer](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/routers/AbstractLendingRouter.sol#L260) is called to set transient variables `t_AllowTransfer_To and t_AllowTransfer_Amount`
```solidity
219     function allowTransfer(
220         address to, uint256 amount, address currentAccount
221     ) external setCurrentAccount(currentAccount) onlyLendingRouter {
222         // Sets the transient variables to allow the lending market to transfer shares on exit position
223         // or liquidation.
224         t_AllowTransfer_To = to;
225         t_AllowTransfer_Amount = amount;
226     }
```
3. then [IYieldStrategy(vault).burnShares](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/routers/AbstractLendingRouter.sol#L265-L267) will be called.
4. in [AbstractYieldStrategy.burnShares](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/AbstractYieldStrategy.sol#L207C14-L217), `_burnShares` will be called in [AbstractYieldStrategy.sol#L213](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/AbstractYieldStrategy.sol#L213)
5. at the end of [AbstractYieldStrategy._burnShares](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/AbstractYieldStrategy.sol#L416-L437), [_burn](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/AbstractYieldStrategy.sol#L436) will be called.
6. winthin `_burn` function, [AbstractYieldStrategy._update](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/AbstractYieldStrategy.sol#L333-L345) will be called. 

**Please note at [AbstractYieldStrategy.sol#L334](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/AbstractYieldStrategy.sol#L334), only when `from` and `to` both are not zero, the transient variables will be reset**.
When `_update` is called by `_burn`, `to` will be **zero**, so the [if branch](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/AbstractYieldStrategy.sol#L334-L342) are skipped, **which means the transient variables are not cleared.**

```solidity
333     function _update(address from, address to, uint256 value) internal override {
334         if (from != address(0) && to != address(0)) {
335             // Any transfers off of the lending market must be authorized here, this means that native balances
336             // held cannot be transferred.
337             if (t_AllowTransfer_To != to) revert UnauthorizedLendingMarketTransfer(from, to, value);
338             if (t_AllowTransfer_Amount < value) revert UnauthorizedLendingMarketTransfer(from, to, value);
339 
340             delete t_AllowTransfer_To;
341             delete t_AllowTransfer_Amount;
342         }
343 
344         super._update(from, to, value);
345     }
```


### Internal Pre-conditions

None

### External Pre-conditions

None

### Attack Path

`AbstractLendingRouter.exitPosition` is called


### Impact

transient variables `t_AllowTransfer_To` and `t_AllowTransfer_Amount` might break the invariants in some case.


### PoC

_No response_

### Mitigation

_No response_

# Issue M-9: Redemption Swap Uses Invalid Pool on Arbitrum for Pendle sUSDe Strategy 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/626 

## Found by 
0xShoonya, talfao

### Summary

The `_executeInstantRedemption(...)` function includes a hardcoded Curve V2 pool address (`0x167478921b907422F8E88B43C4Af2B8BEa278d3A`) used for swapping `sUSDe` to `sDAI`. While this address is valid on Ethereum mainnet, it does **not exist on Arbitrum**. As a result, if this code is deployed or called on Arbitrum, the redemption flow will fail due to the inability to execute the swap.

### Root Cause

In the redemption logic, the Curve V2 pool is hardcoded as follows [PendlePT_sUSDe.sol#L42](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/staking/PendlePT_sUSDe.sol#L42):

```solidity
pool: 0x167478921b907422F8E88B43C4Af2B8BEa278d3A, // @audit-issue
````

This pool exists on Ethereum mainnet but **not** on Arbitrum. There is no fallback logic or per-chain configuration to handle such cases, leading to failure when executed outside Ethereum.

### Internal Pre-conditions

1. Protocol is deployed or used on Arbitrum.
2. User triggers `_executeInstantRedemption(...)`.

### External Pre-conditions

None.

### Attack Path / Failure Scenario

1. A user performs instant redemption on Arbitrum.
2. The contract attempts to execute a swap via the hardcoded Curve pool.
3. The call fails because the pool does not exist on Arbitrum.
4. The transaction reverts, preventing the redemption and potentially disrupting protocol flow.

### Impact

* **Redemptions break on Arbitrum**, blocking access to funds.

### PoC

Confirmed via block explorer — the pool `0x167478921b907422F8E88B43C4Af2B8BEa278d3A` does not exist on Arbitrum.

### Mitigation

* Remove hardcoded pool addresses and replace with dynamic or per-chain configuration.
* Introduce a registry or mapping of chain-specific Curve pool addresses.
* Add validation to ensure pools exist and are callable on the active chain before executing swaps.

```

Let me know if you want this framed as **Medium or High** severity or if you want to pair it with a code snippet fix suggestion.
```


# Issue M-10: Incompatibility of `ERC20::approve` function with USDT tokens on Ethereum Mainnet chain 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/652 

## Found by 
Atharv, Bigsam, KungFuPanda, Ledger\_Patrol, Pro\_King, X0sauce, bretzel, bube, h2134, harry, mgf15, sebar1018, theweb3mechanic, yoooo

## Summary

The `ERC-20` standard specifies that [`approve`](https://github.com/Creepybits/openzeppelin/blob/ecafeabad405536f647ac07567a1d74ad60eb14f/contracts/token/ERC20/ERC20.sol#L81) function should return a bool indicating success. However, some widely-used tokens such as `USDT` omit the return value. When interacting with such tokens using high-level Solidity calls (`ERC20(token).approve`), the EVM expects a return value. If none is returned, decoding fails and the transaction reverts.

## Root Cause

The [`AbstractLendingRouter::_enterOrMigrate`](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/routers/AbstractLendingRouter.sol#L222C5-L245C6) function, [`MorphoLendingRouter::_supplyCollateral`](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/routers/MorphoLendingRouter.sol#L150C5-L164C6) function, [`AbstractStakingStrategy::_mintYieldToken`](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/staking/AbstractStakingStrategy.sol#L77C5-L81C1) and GenericERC4626::_stakeTokens use the `ERC20::approve` function to approve a given amount of asset/token:

```solidity

function _enterOrMigrate(
        address onBehalf,
        address vault,
        address asset,
        uint256 assetAmount,
        bytes memory depositData,
        address migrateFrom
    ) internal returns (uint256 sharesReceived) {
        if (migrateFrom != address(0)) {
            // Allow the previous lending router to repay the debt from assets held here.
            ERC20(asset).checkApprove(migrateFrom, assetAmount);
            sharesReceived = ILendingRouter(migrateFrom).balanceOfCollateral(onBehalf, vault);

            // Must migrate the entire position
            ILendingRouter(migrateFrom).exitPosition(
                onBehalf, vault, address(this), sharesReceived, type(uint256).max, bytes("")
            );
        } else {
@>          ERC20(asset).approve(vault, assetAmount);
            sharesReceived = IYieldStrategy(vault).mintShares(assetAmount, onBehalf, depositData);
        }

        _supplyCollateral(onBehalf, vault, asset, sharesReceived);
    }

    function _supplyCollateral(
        address onBehalf,
        address vault,
        address asset,
        uint256 sharesReceived
    ) internal override {
        MarketParams memory m = marketParams(vault, asset);

        // Allows the transfer from the lending market to the Morpho contract
        IYieldStrategy(vault).allowTransfer(address(MORPHO), sharesReceived, onBehalf);

        // We should receive shares in return
    @>  ERC20(vault).approve(address(MORPHO), sharesReceived);
        MORPHO.supplyCollateral(m, sharesReceived, onBehalf, "");
    }

    function _mintYieldTokens(uint256 assets, address /* receiver */, bytes memory depositData) internal override virtual {
@>      ERC20(asset).approve(address(withdrawRequestManager), assets);
        withdrawRequestManager.stakeTokens(address(asset), assets, depositData);
    }

     function _stakeTokens(uint256 amount, bytes memory /* stakeData */) internal override {
@>      ERC20(STAKING_TOKEN).approve(address(YIELD_TOKEN), amount);
        IERC4626(YIELD_TOKEN).deposit(amount, address(this));
    }


```

According to the `README` the contract will be deployed on Ethereum Mainnet chain and will use USDT tokens.

The problem is that the `ERC20` interface expects the `approve` function to return a boolean value, but `USDT` token on Ethereum dosn't have a [return value](https://etherscan.io/address/0xdAC17F958D2ee523a2206206994597C13D831ec7#code#L199). This means the approve operation of the tokens will always revert.

Also these functions don't set first the allowance to 0. In normal circumstances, the previous allowance should be used and the current allowance should be 0, but if the current allowance is not 0, the approve function will revert again. The `approve` function of the `USDT` token expects the allowance to be 0 before setting the new one.

## Impact

Users are unable to use properly important functions of the protocol like entering or migrating a vault, minting yield tokens or staking tokens with USDT token on Ethereum mainnet chain, these functions will always revert due to the use of `ERC20::approve` function. USDT is one of the tokens that the protocol will use, therefore the failure to handle its non-boolean approve return is a critical issue due to breaking core functionality for a supported token.

## PoC

The following test shows that the approve function will revert for `USDT` token on Ethereum Mainnet chain:

```solidity

    function testApproveMainnet() public{
        address user = address(0x123);
        ethFork = vm.createFork(ETH_RPC_URL);
        vm.selectFork(ethFork);
        assetUsdtETH = IERC20(usdtETH);
        
        deal(address(assetUsdtETH), user, 100*10**6, true);

        vm.startPrank(user);
        vm.expectRevert();
        assetUsdtETH.approve(address(0x444), 10*10**6);
    }

```

## Mitigation

Use OpenZeppelin's `SafeERC20::forceApprove` function instead of `IERC20::approve` function.


# Issue M-11: User unable to migrate under certain edge case 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/674 

## Found by 
0xRstStn, 0xpiken, Bigsam, Bizarro, EFCCWEB3, Ledger\_Patrol, Oxsadeeq, Ragnarok, Riceee, X0sauce, aman, bretzel, coffiasd, dan\_\_vinci, dhank, h2134, hard1k, jprod15, mstpr-brainbot, n1ikh1l, rudhra1749, shiazinho, talfao, theweb3mechanic, touristS, wickie, xiaoming90

### Summary

-

### Root Cause

-

### Internal Pre-conditions

-

### External Pre-conditions

-

### Attack Path

During migration, the `assetToRepay` parameter of the `_exitWithRepay` function is always set to `type(uint256).max`, as shown in Line 237 below.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/routers/AbstractLendingRouter.sol#L237

```solidity
File: AbstractLendingRouter.sol
221:     /// @dev Enters a position or migrates shares from a previous lending router
222:     function _enterOrMigrate(
223:         address onBehalf,
224:         address vault,
225:         address asset,
226:         uint256 assetAmount,
227:         bytes memory depositData,
228:         address migrateFrom
229:     ) internal returns (uint256 sharesReceived) {
230:         if (migrateFrom != address(0)) {
231:             // Allow the previous lending router to repay the debt from assets held here.
232:             ERC20(asset).checkApprove(migrateFrom, assetAmount);
233:             sharesReceived = ILendingRouter(migrateFrom).balanceOfCollateral(onBehalf, vault);
234: 
235:             // Must migrate the entire position
236:             ILendingRouter(migrateFrom).exitPosition(
237:                 onBehalf, vault, address(this), sharesReceived, type(uint256).max, bytes("")
238:             );
239:         } else {
```

Assume that Bob has supplied collateral, but no debt, and he wants to migrate from the previous lending router to a new lending router.

Since `assetToRepay` is set to `type(uint256).max`, the `assetToRepay` will be overwritten to zero (0) in Line 193 below. In addition, since Bob does not have any debt, which means that he has no borrow shares, the `MORPHO.position(morphoId(m), onBehalf).borrowShares` at Line 192 below will return zero (0). In this case, `sharesToRepay` will be zero (0)

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/routers/MorphoLendingRouter.sol#L192

```solidity
File: MorphoLendingRouter.sol
177:     function _exitWithRepay(
178:         address onBehalf,
179:         address vault,
180:         address asset,
181:         address receiver,
182:         uint256 sharesToRedeem,
183:         uint256 assetToRepay,
184:         bytes calldata redeemData
185:     ) internal override {
186:         MarketParams memory m = marketParams(vault, asset);
187: 
188:         uint256 sharesToRepay;
189:         if (assetToRepay == type(uint256).max) {
190:             // If assetToRepay is uint256.max then get the morpho borrow shares amount to
191:             // get a full exit.
192:             sharesToRepay = MORPHO.position(morphoId(m), onBehalf).borrowShares;
193:             assetToRepay = 0;
194:         }
195: 
196:         bytes memory repayData = abi.encode(
197:             onBehalf, vault, asset, receiver, sharesToRedeem, redeemData, _isMigrate(receiver)
198:         );
199: 
200:         // Will trigger a callback to onMorphoRepay
201:         MORPHO.repay(m, assetToRepay, sharesToRepay, onBehalf, repayData);
202:     }

```

Note that both `assetToRepay` and `sharesToRepay` are zero (0). At Line 201 above, the `Morpho.repay()` function will be executed with the following parameter values:

```solidity
MORPHO.repay(m, assetToRepay, sharesToRepay, onBehalf, repayData); 
MORPHO.repay(m, 0, 0, onBehalf, repayData); 
```

When inspecting Morpho's `Morpho.repay()` function, the repay function will revert at Line 278 due to the `UtilsLib.exactlyOneZero(assets, shares)` check because `assets` and `shares` cannot be both zero at the same time.

https://github.com/morpho-org/morpho-blue/blob/731e3f7ed97cf15f8fe00b86e4be5365eb3802ac/src/Morpho.sol#L278

```solidity
File: Morpho.sol
269:     function repay(
270:         MarketParams memory marketParams,
271:         uint256 assets, // @audit-info if migrate, assets = assetToRepay = 0
272:         uint256 shares, // @audit-info if migrate, shares = MORPHO.position(morphoId(m), onBehalf).borrowShares;
273:         address onBehalf,
274:         bytes calldata data
275:     ) external returns (uint256, uint256) {
276:         Id id = marketParams.id();
277:         require(market[id].lastUpdate != 0, ErrorsLib.MARKET_NOT_CREATED);
278:         require(UtilsLib.exactlyOneZero(assets, shares), ErrorsLib.INCONSISTENT_INPUT);
279:         require(onBehalf != address(0), ErrorsLib.ZERO_ADDRESS);
```

https://github.com/morpho-org/morpho-blue/blob/731e3f7ed97cf15f8fe00b86e4be5365eb3802ac/src/libraries/UtilsLib.sol#L13

```solidity
File: UtilsLib.sol
11: library UtilsLib {
12:     /// @dev Returns true if there is exactly one zero among `x` and `y`.
13:     function exactlyOneZero(uint256 x, uint256 y) internal pure returns (bool z) {
14:         assembly {
15:             z := xor(iszero(x), iszero(y))
16:         }
17:     }
```

### Impact

Medium. Migration function is a core functionality in the protocol. This report shows that the migration will be DOS or not work under certain edge case.

### PoC

_No response_

### Mitigation

Skip the repayment if debt is zero, and proceed with the migration.

# Issue M-12: Unable to deposit to Convex in Arbitrum 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/678 

## Found by 
Bluedragon, Riceee, bretzel, dan\_\_vinci, elolpuer, khaye26, touristS, xiaoming90

### Summary

-

### Root Cause

-

### Internal Pre-conditions

-

### External Pre-conditions

-

### Attack Path

Per the contest's README, Base and Arbitrum are in-scope for this contest. Sherlock's Judge has further confirmed this in the Discord channel.

> Q: On what chains are the smart contracts going to be deployed?
> Ethereum, in the future we will consider Base or Arbitrum

It was found that the Curve LP token will be deposited to Convex via the `IConvexBooster(CONVEX_BOOSTER).deposit(CONVEX_POOL_ID, lpTokens, true)` interface/function.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/single-sided-lp/CurveConvex2Token.sol#L291

```solidity
File: CurveConvex2Token.sol
291:     function _stakeLpTokens(uint256 lpTokens) internal {
292:         if (CONVEX_BOOSTER != address(0)) {
293:             bool success = IConvexBooster(CONVEX_BOOSTER).deposit(CONVEX_POOL_ID, lpTokens, true);
294:             require(success);
295:         } else {
296:             ICurveGauge(CURVE_GAUGE).deposit(lpTokens);
297:         }
298:     }
```

The following is that Booster contract address taken from the official documentation (https://docs.convexfinance.com/convexfinance/faq/contract-addresses):

Ethereum

- Booster(main deposit contract): [0xF403C135812408BFbE8713b5A23a04b3D48AAE31](https://etherscan.io/address/0xF403C135812408BFbE8713b5A23a04b3D48AAE31)

```python
//deposit lp tokens and stake
function deposit(uint256 _pid, uint256 _amount, bool _stake) public returns(bool){
    require(!isShutdown,"shutdown");
    PoolInfo storage pool = poolInfo[_pid];
    require(pool.shutdown == false, "pool is closed");
```

Arbitrum

- Booster: [0xF403C135812408BFbE8713b5A23a04b3D48AAE31](https://arbiscan.io/address/0xF403C135812408BFbE8713b5A23a04b3D48AAE31)

```python
//deposit lp tokens and stake
function deposit(uint256 _pid, uint256 _amount) public returns(bool){
    require(!isShutdown,"shutdown");
    PoolInfo storage pool = poolInfo[_pid];
    require(pool.shutdown == false, "pool is closed");
```

Notice that the interface of the `deposit` function in Arbitrum is different from Ethereum. Arbitum's deposit function only accept two parameters while Ethereum's deposit function requires three parameters.

Thus, when attempting to deposit Curve LP tokens to Convex in Arbitrum, the transaction revert due to incorrect function interfaces.

### Impact

The protocol will not work because staking the LP token will cause the entire transaction to revert, preventing anyone from entering the position.

### PoC

_No response_

### Mitigation

```diff
function _stakeLpTokens(uint256 lpTokens) internal {
    if (CONVEX_BOOSTER != address(0)) {
+    		bool success;
+    		if (Deployments.CHAIN_ID == Constants.CHAIN_ID_MAINNET) {
-        		bool success = IConvexBooster(CONVEX_BOOSTER).deposit(CONVEX_POOL_ID, lpTokens, true);
+						success = IConvexBooster(CONVEX_BOOSTER).deposit(CONVEX_POOL_ID, lpTokens, true);
        } else if (Deployments.CHAIN_ID == Constants.CHAIN_ID_ARBITRUM) {
+	        	success = IConvexBoosterArbitrum(CONVEX_BOOSTER).deposit(CONVEX_POOL_ID, lpTokens);
+        }
        require(success);
    } else {
        ICurveGauge(CURVE_GAUGE).deposit(lpTokens);
    }
}
```

# Issue M-13: Certain Curve V2 pool cannot be supported 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/683 

## Found by 
xiaoming90

### Summary

-

### Root Cause

-

### Internal Pre-conditions

-

### External Pre-conditions

-

### Attack Path

The protocol is designed to support Curve V2 pool.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/interfaces/Curve/ICurve.sol#L4

```solidity
File: ICurve.sol
4: enum CurveInterface {
5:     V1,
6:     V2,
7:     StableSwapNG
8: }
```

The protocol interacts with Curve V2 pool via the `remove_liquidity()` function, which accepts four (4) parameters. Notice that the third parameter is a boolean, and the fourth (last) parameter is an address.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/single-sided-lp/CurveConvex2Token.sol#L156

```solidity
File: CurveConvex2Token.sol
146:     function checkReentrancyContext() external {
..SNIP..
153:         } else if (CURVE_INTERFACE == CurveInterface.V2) {
154:             // Curve V2 does a `-1` on the liquidity amount so set the amount removed to 1 to
155:             // avoid an underflow.
156:             ICurve2TokenPoolV2(CURVE_POOL).remove_liquidity(1, minAmounts, true, address(this));
```

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/single-sided-lp/CurveConvex2Token.sol#L281

```solidity
File: CurveConvex2Token.sol
244:     function _exitPool(
245:         uint256 poolClaim, uint256[] memory _minAmounts, bool isSingleSided
246:     ) internal returns (uint256[] memory exitBalances) {
..SNIP..
279:                 // Remove liquidity on CurveV2 does not return the exit amounts so we have to measure
280:                 // them before and after.
281:                 ICurve2TokenPoolV2(CURVE_POOL).remove_liquidity(
282:                     // Last two parameters are useEth = true and receiver = this contract
283:                     poolClaim, minAmounts, true, address(this)
284:                 );
```

This is aligned with the `remove_liquidity()` interface of Curve V2 (version 0.3.1) pool, where the pool type is "Two Coin CryptoSwap" as shown below. Some examples of such pools are:

- https://www.curve.finance/dex/ethereum/pools/teth/deposit/ (t/ETH)
- https://www.curve.finance/dex/ethereum/pools/factory-crypto-230/deposit/ (LPXCVX/CVX)

```python
# @version 0.3.1
# (c) Curve.Fi, 2021
# Pool for two crypto assets

# Expected coins:
# eth/whatever
..SNIP..
@external
@nonreentrant('lock')
def remove_liquidity(_amount: uint256, min_amounts: uint256[N_COINS],
                     use_eth: bool = False, receiver: address = msg.sender):
    """
    This withdrawal method is very safe, does no complex math
    """
```

However, the problem is that there is another Curve V2 ("Two Coin CryptoSwap"), and the version is 0.3.0. Examples of such pools are the https://www.curve.finance/dex/ethereum/pools/eursusd/deposit/ (eursusd).

If the code attempts to remove liquidity, the transaction will revert as the `remove_liquidity()` function only accepts three (3) input parameters, as shown below.

```python
# @version 0.3.0
# (c) Curve.Fi, 2021
# Pool for two crypto assets

from vyper.interfaces import ERC20
# Expected coins:
# eth/whatever
..SNIP..
@external
@nonreentrant('lock')
def remove_liquidity(_amount: uint256, min_amounts: uint256[N_COINS], use_eth: bool = False):
    """
    This withdrawal method is very safe, does no complex math
    """
    _coins: address[N_COINS] = coins
    total_supply: uint256 = CurveToken(token).totalSupply()
```

The similar issue also occurs for the `add_liquidity()` function, as the function interface for various Curve V2 pools (0.3.1 and 0.3.0) are different. Note that both 0.3.1 and 0.3.0 are valid Curve V2 pools that are still running live in Curve protocol today.

```python
# @version 0.3.0
# (c) Curve.Fi, 2021
# Pool for two crypto assets
..SNIP..
def add_liquidity(amounts: uint256[N_COINS], min_mint_amount: uint256, use_eth: bool = False) -> uint256:
```

```python
# @version 0.3.1
# (c) Curve.Fi, 2021
# Pool for two crypto assets
..SNIP..
# Expected coins:
# eth/whatever
def add_liquidity(amounts: uint256[N_COINS], min_mint_amount: uint256,
                  use_eth: bool = False, receiver: address = msg.sender) -> uint256:
```

Per the [contest's README](https://github.com/sherlock-audit/2025-06-notional-exponent-xiaoming9090/tree/main?tab=readme-ov-file#q-please-discuss-any-design-choices-you-made), the protocol is designed to be extendable to new yield strategies and opportunities.

> Q: Please discuss any design choices you made.
> Notional Exponent is designed to be extendable to new yield strategies and opportunities as well as new lending platforms. 

However, in this case, it is shown that certain Curve V2 pools cannot be supported, which does not meet the requirements.

### Impact

Medium. Core functionality is broken.


### PoC

_No response_

### Mitigation

_No response_

# Issue M-14: Lack of minimum debt threshold enables unliquidatable small positions 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/684 

## Found by 
0xKemah, 0xenzo, Audinarey, EddiePumpin, LhoussainePh, Pro\_King, SOPROBRO, jasonxiale, molaratai, oxwhite, theweb3mechanic

### Summary

The protocol allows users to repay debt partially through the `exitPosition()` function, even if a minimal amount of debt remains (e.g., 1 wei). Since liquidation incentives are proportional to the repaid debt and gas costs are fixed, such positions offer no economic incentive for liquidators. As a result, these small debt positions accumulate over time, becoming unliquidatable and potentially leading to long-term protocol insolvency.

### Root Cause

When users open a position without providing upfront collateral by calling [`enterPosition()` ](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/routers/AbstractLendingRouter.sol#L56)with a non-zero `borrowAmount` and a `depositAssetAmount` of zero. The protocol takes a flashloan from Morpho for the borrow amount, mints shares with it, supplies those shares as collateral to Morpho, and then borrows the same amount to repay the flashloan resulting in a position where collateral equals the borrowed amount.
 If a deposit is provided, the collateral becomes greater than the debt.  So `collateral` can be `>=` `borrowAmmount` .
 This logic enables fully collateralized positions with little or no initial user capital.
```javascript
//AbstractLendingRouter.sol

L56:  function enterPosition(
        address onBehalf,
        address vault,
        uint256 depositAssetAmount,
        uint256 borrowAmount,
        bytes calldata depositData
    ) public override isAuthorized(onBehalf, vault) {
        _enterPosition(onBehalf, vault, depositAssetAmount, borrowAmount, depositData, address(0));
    }

L79:   function _enterPosition(
        address onBehalf,
        address vault,
        uint256 depositAssetAmount,
        uint256 borrowAmount,
        bytes memory depositData,
        address migrateFrom
    ) internal {
       ...
@>        if (depositAssetAmount > 0) {
            // Take any margin deposit from the sender initially
            ERC20(asset).safeTransferFrom(msg.sender, address(this), depositAssetAmount);
        }

  @>      if (borrowAmount > 0) {
            _flashBorrowAndEnter(
                onBehalf, vault, asset, depositAssetAmount, borrowAmount, depositData, migrateFrom
            );
        } else {
            _enterOrMigrate(onBehalf, vault, asset, depositAssetAmount, depositData, migrateFrom);
...
```

When repaying through `exitPosition()`,
```javascript
//AbstractLendingRouter.sol

    function exitPosition(
        address onBehalf,
        address vault,
        address receiver,
        uint256 sharesToRedeem,
        uint256 assetToRepay,
        bytes calldata redeemData
    ) external override isAuthorized(onBehalf, vault) {
        _checkExit(onBehalf, vault);

        address asset = IYieldStrategy(vault).asset();
        if (0 < assetToRepay) {
L120:            _exitWithRepay(onBehalf, vault, asset, receiver, sharesToRedeem, assetToRepay, redeemData);
        } else {
...
}
```
 a borrower can make partial repayments that reduce their debt to extremely small amounts, such as 1 wei. These minimal debt positions offer no meaningful incentive for liquidators, who must cover fixed gas costs to execute liquidation but receive rewards that are too small especially on Ethereum mainnet which is the only chain the contract will be deployed to.

### Internal Pre-conditions

- Borrower must borrow small amounts such as 1 wei.
- Or reduce his debt positions to 1 wei

### External Pre-conditions

none

### Attack Path

none 

### Impact


- Positions with tiny debt amounts remain permanently unliquidated.

- Over time, these accumulate and skew the protocol’s debt accounting and solvency assumptions.

### PoC

_No response_

### Mitigation

- Enforce a minimum borrow size
- Or prevent users from leaving behind trivial debt after repay or withdrawal.

# Issue M-15: Migration will not work due to insufficient borrowed amount to cover the flash-loan 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/690 

## Found by 
xiaoming90

### Summary

-

### Root Cause

-

### Internal Pre-conditions

-

### External Pre-conditions

-

### Attack Path

The migration will not work under certain conditions.

Assume a Yield Strategy Vault with the following setup:

- Yield token is equal to wstETH
- Share name = YS-wstETH

Assume that in the current Morph pool, the collateral is YS-wstETH share, and its LTV = 0.8. Each YS-wsETH is worth 500.

Currently, two (2) YS-wsETH is deposited as collateral by Bob in his position, so his collateral value is worth 1000, while he has a debt of 800. This is permitted because `1000 value * 0.8 (LTV) = 800`.

Bob intends to migrate to a newer Morpho Fixed pool or a different lending protocol. Assume that Bob wants to migrate to $LendingProtocol_X$.

1. The migration works by only utilizing the flash loan to repay the old debt. The protocol will flash loan 800 from the new $LendingProtocol_X$ and use it to repay the old debt (800) in the current Morpho pool.

2. Once the old debt in the Morpho pool has been cleared, the two (2) YS-wstETH will be withdrawn from the old Morpho pool.
3. Two (2) YS-wstETH will be deposited into the new $LendingProtocol_X$ as collateral, and the code will borrow an additional 800 to cover the flash-loan amount of 800.

However, the main problem here is that there is no guarantee that the LTV of YS-wstETH shares in the new $LendingProtocol_X$ remain the same as the old Morpho pool (0.8). 

Assume that the LTV of YS-wstETH shares in the new $LendingProtocol_X$ is 0.6. In this case, the maximum amount that can be borrowed is only 600. So, there is a shortfall of 200 here. As such, it is insufficient to cover the flash-loan amount of 800, and the migration will revert.

During migration, the amount of assets you want to deposit or top up is hardcoded at zero, as shown in Line 76 below. Thus, there is no way for Bob to top up or deposit 200 to cover the shortfall, even if he wishes.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/routers/AbstractLendingRouter.sol#L76

```solidity
File: AbstractLendingRouter.sol
67:     function migratePosition(
68:         address onBehalf,
69:         address vault,
70:         address migrateFrom
71:     ) public override isAuthorized(onBehalf, vault) {
72:         if (!ADDRESS_REGISTRY.isLendingRouter(migrateFrom)) revert InvalidLendingRouter();
73:         // Borrow amount is set to the amount of debt owed to the previous lending router
74:         (uint256 borrowAmount, /* */, /* */) = ILendingRouter(migrateFrom).healthFactor(onBehalf, vault);
75: 
76:         _enterPosition(onBehalf, vault, 0, borrowAmount, bytes(""), migrateFrom); // @audit-info depositAssetAmount => 0, depositData => ""
77:     }
```

### Impact

Migration is a core functionality of the protocol. As shown in the report, the migration function is broken.

### PoC

_No response_

### Mitigation

Allow users to top up or deposit the shortfall during the migration process.


# Issue M-16: Funds stuck if one of the withdrawal requests cannot be finalized 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/692 

## Found by 
HeckerTrieuTien, Ledger\_Patrol, auditgpt, coin2own, dan\_\_vinci, xiaoming90

### Summary

-

### Root Cause

- Handling of multiple withdraw requests (WRs) is not robust enough, and the failure of one can cause the entire WRs to be stuck even though the rest of the WRs have finalized successfully.
- Lack of minimum position size could cause a revert to occur during redemption, blocking the WR from finalizing. See the main report for more details.

### Internal Pre-conditions

-

### External Pre-conditions

-

### Attack Path

Both WRs must be finalized before the redemption is allowed to be executed, as shown in Line 397 below.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/single-sided-lp/AbstractSingleSidedLP.sol#L397

```solidity
File: AbstractSingleSidedLP.sol
378:     function finalizeAndRedeemWithdrawRequest(
379:         address sharesOwner,
380:         uint256 sharesToRedeem
381:     ) external override returns (uint256[] memory exitBalances, ERC20[] memory withdrawTokens) {
382:         ERC20[] memory tokens = TOKENS();
383: 
384:         exitBalances = new uint256[](tokens.length);
385:         withdrawTokens = new ERC20[](tokens.length);
386: 
387:         WithdrawRequest memory w;
388:         for (uint256 i; i < tokens.length; i++) {
389:             IWithdrawRequestManager manager = ADDRESS_REGISTRY.getWithdrawRequestManager(address(tokens[i]));
390:             (w, /* */) = manager.getWithdrawRequest(address(this), sharesOwner);
391: 
392:             uint256 yieldTokensBurned = uint256(w.yieldTokenAmount) * sharesToRedeem / w.sharesAmount;
393:             bool finalized;
394:             (exitBalances[i], finalized) = manager.finalizeAndRedeemWithdrawRequest({
395:                 account: sharesOwner, withdrawYieldTokenAmount: yieldTokensBurned, sharesToBurn: sharesToRedeem
396:             });
397:             if (!finalized) revert WithdrawRequestNotFinalized(w.requestId);
398:             withdrawTokens[i] = ERC20(manager.WITHDRAW_TOKEN());
399:         }
400:     }
```

However, the issue is that if one of the WRs cannot be finalized due to various reasons, such as:

- Insufficient funds/liquidity at the external protocol
- Validator of the Liquid Staking protocol suffers a massive slashing event, leading to insufficient liquidity to repay users
- External protocol being compromised or paused
- External protocol's finalize redemption/withdrawal function keeps reverting (can be due to an unintentional bug or malicious acts)
- If the WR is handling ERC4626 vault share, it sometimes might revert during redemption. A common revert during redemption is a classic zero share check (e.g., `require((assets = previewRedeem(shares)) != 0, "ZERO_ASSETS");)` that blocks the redemption when the assets received are zero, which might occur due to rounding errors. This generally occurs when the share to be redeemed is small, and since Notional does not enforce a minimum position size, this issue can theoretically arise. One example of such is the PirexETH that is in-scope, where it will revert if the assets received round down to zero (see [here](https://etherscan.io/address/0xD664b74274DfEB538d9baC494F3a4760828B02b0#code#F23#L107)). Same for AutoPxETH (See [here](https://etherscan.io/address/0x9ba021b0a9b958b5e75ce9f6dff97c7ee52cb3e6#code#F3#L107)). There are two (2) root causes here: 1) Lack of minimum position size 2) Handling of multiple WRs are not robust enough and the failure of one can cause entire WRs to be stuck.
- To add-on to the previous point, some staking protocols (e.g., LIDO) enforced a minimum withdrawal amount. If the amount of LST to be unstaked is less than the minimum withdrawal amount, the redemption cannot be carried out. LIDO is one of the protocols that enforce this. Since there is no minimum position size when entering the position, this is likely to occur. In this case, such a WR cannot be finalized or even initiate withdrawal. Since the Contest's README [here](https://github.com/sherlock-audit/2025-06-notional-exponent-xiaoming9090/tree/main?tab=readme-ov-file#q-please-discuss-any-design-choices-you-made), mentioned that `Notional Exponent is designed to be extendable to new yield strategies and opportunities as well as new lending platforms. `, this point is valid as this issue will occur when they extended to other platforms such as LIDO.

The funds in the other WR will remain stuck and be lost.

Assume a Curve two-token pool with wstETH (7-day withdrawal period + subject to redemption queue) and USDC (no withdrawal period).

When the user initiates the withdrawal, there will be two (2) separate withdrawal requests (WR) created. First WR holds 100 wstETH and is currently pending the withdrawal period to be completed, while the second WR holds 115 WETH.

If LIDO is compromised, the first WR will not be able to be finalized, as there is no guarantee that LIDO's redemption will resume after the hack, as they may not recover from the hack.

In this case, since the requirement is that both WRs must be finalized, even though the 115 WETH can be withdrawn immediately, the protocol doesn't allow the user to do so. Thus, instead of losing around 50% of the total funds due to the LIDO hack, the user ends up allowing 100% of the funds as the entire fund is stuck.

### Impact

High. Funds will get stuck if this issue happens.


### PoC

_No response_

### Mitigation

_No response_

# Issue M-17: Unable to unstake Curve LP tokens from Arbitrum 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/701 

## Found by 
xiaoming90

### Summary

-

### Root Cause

-

### Internal Pre-conditions

-

### External Pre-conditions

-

### Attack Path

Per the contest's README, Base and Arbitrum are in-scope for this contest. Sherlock's Judge has further confirmed this in the Discord channel.

> Q: On what chains are the smart contracts going to be deployed?
> Ethereum, in the future we will consider Base or Arbitrum

Per the Convex documentation, it mentioned the following:

> Unlike mainnet, there is no more "WithdrawAndUnwrap" option. The only withdraw function is now a plain withdraw(uint256 _amount, bool _claim) or withdrawAll(bool claim).   This will return the Curve LP token much like the "unwrap" method on mainnet.

However, it was found that Notional unstakes the Curve LP token via the `withdrawAndUnwrap()` function regardless of whether it is Ethereum or Arbitrum chain.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/single-sided-lp/CurveConvex2Token.sol#L301

```solidity
File: CurveConvex2Token.sol
301:     function _unstakeLpTokens(uint256 poolClaim) internal {
302:         if (CONVEX_REWARD_POOL != address(0)) {
303:             bool success = IConvexRewardPool(CONVEX_REWARD_POOL).withdrawAndUnwrap(poolClaim, false);
304:             require(success);
305:         } else {
306:             ICurveGauge(CURVE_GAUGE).withdraw(poolClaim);
307:         }
308:     }
```

As a result, on Arbitrum, the Curve LP tokens will not be able to be unstake from Convex, leading to the user's funds being stuck.

The following shows that only `withdraw()` and `withdrawAll()` functions are supported in Arbitrum's ConvexRewardPool. The `withdrawAndUnwrap()` function is not supported in Arbitrum.

https://arbiscan.io/address/0xFDC6304b38d0703F0D0d13b665ceE92499039383#code#F1#L385

```solidity
    //withdraw balance and unwrap to the underlying lp token
    function withdraw(uint256 _amount, bool _claim) public returns(bool){

        //checkpoint first if claiming, or burn will call checkpoint anyway
        if(_claim){
            //checkpoint with claim flag
            _checkpoint(msg.sender, msg.sender);
        }

        //change state
        //burn will also call checkpoint
        _burn(msg.sender, _amount);

        //tell booster to withdraw underlying lp tokens directly to user
        IBooster(convexBooster).withdrawTo(convexPoolId,_amount,msg.sender);

        emit Withdrawn(msg.sender, _amount);

        return true;
    }
```

https://arbiscan.io/address/0xFDC6304b38d0703F0D0d13b665ceE92499039383#code#F1#L426

```solidity
    //withdraw full balance
    function withdrawAll(bool claim) external{
        withdraw(balanceOf(msg.sender),claim);
    }
```

### Impact

High. Loss of funds, as the user's funds will be stuck. The issue is serious because users can enter the position (aka deposit to the protocol), but cannot withdraw their funds.

### PoC

_No response_

### Mitigation

```diff
    function _unstakeLpTokens(uint256 poolClaim) internal {
        if (CONVEX_REWARD_POOL != address(0)) {
+           bool success;
+           if (Deployments.CHAIN_ID == Constants.CHAIN_ID_MAINNET) {      	
-                      bool success = IConvexRewardPool(CONVEX_REWARD_POOL).withdrawAndUnwrap(poolClaim, false);
+                      success = IConvexRewardPool(CONVEX_REWARD_POOL).withdrawAndUnwrap(poolClaim, false);
+           } else if (Deployments.CHAIN_ID == Constants.CHAIN_ID_ARBITRUM) {
+                      success = IConvexRewardPool(CONVEX_REWARD_POOL).withdraw(poolClaim, false);
+           }
            require(success);
        } else {
            ICurveGauge(CURVE_GAUGE).withdraw(poolClaim);
        }
    }
```

# Issue M-18: Setup with `asset = WETH` and a Curve pool that contains Native ETH will lead to a loss for the users 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/708 

## Found by 
xiaoming90

### Summary

-

### Root Cause

-

### Internal Pre-conditions

-

### External Pre-conditions

-

### Attack Path

Assume a Yield Strategy vault where its asset is WETH and the Curve Pool is Native ETH/wstETH.  In this case, calling the `TOKENS()` function will return:

- tokens[0] = Curve's `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE` = Converted to `0x0000` (Native ETH) during initialization
- tokens[1] = 0xB82381A3fBD3FaFA77B3a7bE693342618240067b (wstETH)

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/single-sided-lp/CurveConvex2Token.sol#L162

```solidity
File: CurveConvex2Token.sol
162:     function TOKENS() internal view override returns (ERC20[] memory) {
163:         ERC20[] memory tokens = new ERC20[](_NUM_TOKENS);
164:         tokens[0] = ERC20(TOKEN_1);
165:         tokens[1] = ERC20(TOKEN_2);
166:         return tokens;
167:     }
```

The `_PRIMARY_INDEX` will be set to 0, which is the first token of the Curve pool. The condition at Line 59 will evaluate to `True`.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/single-sided-lp/CurveConvex2Token.sol#L59

```solidity
File: CurveConvex2Token.sol
57:         // Assets may be WETH, so we need to unwrap it in this case.
58:         _PRIMARY_INDEX =
59:             (TOKEN_1 == _asset || (TOKEN_1 == ETH_ADDRESS && _asset == address(WETH))) ? 0 :
60:             (TOKEN_2 == _asset || (TOKEN_2 == ETH_ADDRESS && _asset == address(WETH))) ? 1 :
61:             // Otherwise the primary index is not set and we will not be able to enter or exit
62:             // single sided.
63:             type(uint8).max;
```

During the exiting the position, liquidation, or initiating withdrawal, the LP tokens will be unstaked/redeemed from Curve or Convex. Let's review these three (3) operations.

**Initiating withdrawal**

Initiating withdrawal will eventually call the `unstakeAndExitPool` function below. After calling the `_unstakeLpTokens()` and `_exitPool()` functions in Lines 201 and 203 below, the vault will receive back 100 Native ETH and 100 wstETH (as an example). 


> [!NOTE]
>
> Note that when initiating a withdrawal, it will always exit proportionally, and not single-sided as per [here](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/single-sided-lp/AbstractSingleSidedLP.sol#L276). Users do not have the option to choose whether they want to exit proportionally or single-sidedly during the initiation of a withdrawal.

Subsequently, the 100 Native ETH will be wrapped to 100 WETH in Line 207 below with the `WETH.deposit()` function. So, there is zero Native ETH left in the vault. At this point, the balance of the vault is: 100 WETH + 100 wstETH.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/single-sided-lp/CurveConvex2Token.sol#L207

```solidity
File: CurveConvex2Token.sol
198:     function unstakeAndExitPool(
199:         uint256 poolClaim, uint256[] memory _minAmounts, bool isSingleSided
200:     ) external returns (uint256[] memory exitBalances) {
201:         _unstakeLpTokens(poolClaim);
202: 
203:         exitBalances = _exitPool(poolClaim, _minAmounts, isSingleSided);
204: 
205:         if (ASSET == address(WETH)) {
206:             if (TOKEN_1 == ETH_ADDRESS) {
207:                 WETH.deposit{value: exitBalances[0]}();
208:             } else if (TOKEN_2 == ETH_ADDRESS) {
209:                 WETH.deposit{value: exitBalances[1]}();
210:             }
211:         }
212:     }
```

Since two tokens (Native ETH and wstETH) are being returned, this is not a single-sided exit. Thus, the `_executeRedemptionTrades` function in Line 176 will be executed.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/single-sided-lp/AbstractSingleSidedLP.sol#L176

```solidity
File: AbstractSingleSidedLP.sol
145:     function _redeemShares(
146:         uint256 sharesToRedeem,
147:         address sharesOwner,
148:         bool isEscrowed, // @audit-info True if there is pending withdraw request
149:         bytes memory redeemData
150:     ) internal override {
151:         RedeemParams memory params = abi.decode(redeemData, (RedeemParams));
152: 
153:         // Stores the amount of each token that has been withdrawn from the pool.
154:         uint256[] memory exitBalances;
155:         bool isSingleSided;
156:         ERC20[] memory tokens;
157:         if (isEscrowed) {
158:             // Attempt to withdraw all pending requests, tokens may be different if there
159:             // is a withdraw request.
160:             (exitBalances, tokens) = _withdrawPendingRequests(sharesOwner, sharesToRedeem);
161:             // If there are pending requests, then we are not single sided by definition
162:             isSingleSided = false;
163:         } else {
164:             isSingleSided = params.redemptionTrades.length == 0;
165:             uint256 yieldTokensBurned = convertSharesToYieldToken(sharesToRedeem);
166:             exitBalances = _unstakeAndExitPool(yieldTokensBurned, params.minAmounts, isSingleSided);
167:             tokens = TOKENS();
168:         }
169: 
170:         if (!isSingleSided) {
171:             // If not a single sided trade, will execute trades back to the primary token on
172:             // external exchanges. This method will execute EXACT_IN trades to ensure that
173:             // all of the balance in the other tokens is sold for primary.
174:             // Redemption trades are not automatically enabled on vaults since the trading module
175:             // requires explicit permission for every token that can be sold by an address.
176:             _executeRedemptionTrades(tokens, exitBalances, params.redemptionTrades);
177:         }
178:     }
```

Recall that:

- tokens[0] = 0x0000 (Native ETH)
- tokens[1] = 0xB82381A3fBD3FaFA77B3a7bE693342618240067b (wstETH)

Note that the condition in Line 229 of the `_executeRedemptionTrades()` function below will never be `True` because:

```solidity
if (address(tokens[i]) == address(asset))
if (address(0x0) == WETH)
if (false)
```

In the first iteration of the for-loop, the `Trade.sellToken` will be set to `0x0000` (Native ETH), which means it will attempt to sell 100 Native ETH. However, the issue here is that when it attempts to sell 100 Native ETH, the trade module will revert due to insufficient balance because the vault does not have 100 Native ETH. 

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/single-sided-lp/AbstractSingleSidedLP.sol#L223

```solidity
File: AbstractSingleSidedLP.sol
223:     function _executeRedemptionTrades(
224:         ERC20[] memory tokens,
225:         uint256[] memory exitBalances,
226:         TradeParams[] memory redemptionTrades
227:     ) internal returns (uint256 finalPrimaryBalance) {
228:         for (uint256 i; i < exitBalances.length; i++) {
229:             if (address(tokens[i]) == address(asset)) {
230:                 finalPrimaryBalance += exitBalances[i];
231:                 continue;
232:             }
233: 
234:             TradeParams memory t = redemptionTrades[i];
235:             // Always sell the entire exit balance to the primary token
236:             if (exitBalances[i] > 0) {
237:                 Trade memory trade = Trade({
238:                     tradeType: t.tradeType,
239:                     sellToken: address(tokens[i]),
240:                     buyToken: address(asset),
241:                     amount: exitBalances[i],
242:                     limit: t.minPurchaseAmount,
243:                     deadline: block.timestamp,
244:                     exchangeData: t.exchangeData
245:                 });
246:                 (/* */, uint256 amountBought) = _executeTrade(trade, t.dexId);
247: 
248:                 finalPrimaryBalance += amountBought;
249:             }
250:         }
251:     }
```

Due to the revert, this means that in this setup, none of the users can initiate a withdrawal request because initiating a withdrawal request will always exit proportionally. As shown above, it will ultimately result in a revert.

**Exiting position and liquidation**

How about exiting position and liquidation? Are these two critical operations affected by this revert? If these operations are performed via proportional exit, it will eventually revert the transaction too. However, these operations give callers the option to choose if they want to exit proportional or single-sided.

Let's see if we can workaround this problem by performing a single-side exit by setting `params.redemptionTrades.length == 0` since we already know that proportional exit does not work, as discussed earlier.

When the `_exitPool()` function below is executed, the exit balances will be as follows (assume 1 wstETH = 1 ETH):

- exitBalances[PRIMARY_INDEX] = exitBalances[0] = 200 Native ETH
- exitBalances[1] = 0

200 Native ETH were later swapped for 200 WETH. It works as intended as all LP tokens have been redeemed back to the asset token (200 WETH)

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/single-sided-lp/CurveConvex2Token.sol#L244

```solidity
File: CurveConvex2Token.sol
244:     function _exitPool(
245:         uint256 poolClaim, uint256[] memory _minAmounts, bool isSingleSided
246:     ) internal returns (uint256[] memory exitBalances) {
247:         if (isSingleSided) {
248:             exitBalances = new uint256[](_NUM_TOKENS);
249:             if (CURVE_INTERFACE == CurveInterface.V1 || CURVE_INTERFACE == CurveInterface.StableSwapNG) {
250:                 // Method signature is the same for v1 and stable swap ng
251:                 exitBalances[_PRIMARY_INDEX] = ICurve2TokenPoolV1(CURVE_POOL).remove_liquidity_one_coin(
252:                     poolClaim, int8(_PRIMARY_INDEX), _minAmounts[_PRIMARY_INDEX]
253:                 );
254:             } else {
255:                 exitBalances[_PRIMARY_INDEX] = ICurve2TokenPoolV2(CURVE_POOL).remove_liquidity_one_coin(
256:                     // Last two parameters are useEth = true and receiver = this contract
257:                     poolClaim, _PRIMARY_INDEX, _minAmounts[_PRIMARY_INDEX], true, address(this)
258:                 );
259:             }
260:         } else {
```

In summary, during exiting position and liquidation, the user is always forced to perform a single-sided exit via Curve's `remove_liquidity_one_coin`. Forcing users to perform a single-sided exit is an issue here.

However, the problem here is that due to the AMM and fee math in the Curve pool, any single-asset withdrawals that worsen the pool imbalance will incur a greater imbalance penalty. Thus, if the Curve pool is imbalanced, the single-sided exit will result in fewer assets being received.

### Impact

**Exiting position and liquidation**

High, as this led to a loss of assets during the forced single-sided exit.

The impact is similar to the past Notional contest issues (https://github.com/sherlock-audit/2023-10-notional-judging/issues/87 and https://github.com/sherlock-audit/2023-10-notional-judging/issues/82), which are judged as a valid High.

**Initiating withdrawal request**

Users are unable to initiate a withdrawal request due to a revert. In this case, users are always forced to swap their yield tokens for asset tokens via a DEX, which incurs unnecessary slippage and fees.

### PoC

_No response_

### Mitigation

_No response_

# Issue M-19: Yield Strategy shares can be transferred without lending router approval 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/714 

## Found by 
xiaoming90

### Summary

-

### Root Cause

-

### Internal Pre-conditions

-

### External Pre-conditions

-

### Attack Path

Per the [documentation](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/audit/Documentation.md#yield-strategy) in the contest's repository, one of the key restrictions imposed by the system is that all transfers of yield strategy shares must be approved by the lending router:

> - All transfers must be approved by a lending router. This is in addition to the normal ERC20 approval allowance. This ensures that collateral held on a lending protocol cannot be withdrawn without first going through the Notional lending router.

Per the [contest's README](https://github.com/sherlock-audit/2025-06-notional-exponent-xiaoming9090/tree/main?tab=readme-ov-file#q-please-discuss-any-design-choices-you-made), if there is a way for a lending platform to bypass any system's restriction, this will be considered a valid finding in the context of this contest.

> Q: Please discuss any design choices you made.
>
> Notional Exponent is designed to be extendable to new yield strategies and opportunities as well as new lending platforms. If there are ways to bypass the restrictions put in place by our system by the target lending platform (in this case Morpho) or a yield strategy then that may be a valid finding.

Per the contest's README, it mentioned that the invariant is that a whitelisted lending router must first authorize all vault share transfers.

> Q: What properties/invariants do you want to hold even if breaking them has a low/unknown impact?
>
> All vault share transfers must be first authorized by a whitelisted lending router.

Let's check if a lending platform can transfer yield strategy vault shares without requiring lending router approval, thereby bypassing this restriction and invariant.

It was found that there is a way. In general, the yield strategy vault shares will be deposited in the lending platform as collateral. Thus, the lending platform will hold large amounts of yield strategy shares. The lending platform can call the `AbstractYieldStrategy.redeemNative()`, which will cause all the yield strategy vault shares they hold onto to be burned. Burning tokens is similar to transferring tokens out of an account (e.g., transfer to `address(0)`), in this case.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/AbstractYieldStrategy.sol#L268

```solidity
File: AbstractYieldStrategy.sol
265:     /// @inheritdoc IYieldStrategy
266:     /// @dev We do not set the current account here because valuation is not done in this method.
267:     /// A native balance does not require a collateral check.
268:     function redeemNative(
269:         uint256 sharesToRedeem,
270:         bytes memory redeemData
271:     ) external override nonReentrant returns (uint256 assetsWithdrawn) {
272:         uint256 sharesHeld = balanceOf(msg.sender);
273:         if (sharesHeld == 0) revert InsufficientSharesHeld();
274: 
275:         assetsWithdrawn = _burnShares(sharesToRedeem, sharesHeld, redeemData, msg.sender);
276:         ERC20(asset).safeTransfer(msg.sender, assetsWithdrawn);
277:     }
```

During the burning of tokens (yield strategy vault share here), the `to` parameter will be `address(0)`. As a result, the restriction at Line 334 below will be bypassed. Thus, even without lending router's approval and even though `t_AllowTransfer_To` and `t_AllowTransfer_Amount` transient variables are not set by the lending routers, the lending platform can still proceed to burn the vault shares and retrieve the underlying yield token. This effectively bypasses the system restriction.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/AbstractYieldStrategy.sol#L334

```solidity
File: AbstractYieldStrategy.sol
333:     function _update(address from, address to, uint256 value) internal override {
334:         if (from != address(0) && to != address(0)) {
335:             // Any transfers off of the lending market must be authorized here, this means that native balances
336:             // held cannot be transferred.
337:             if (t_AllowTransfer_To != to) revert UnauthorizedLendingMarketTransfer(from, to, value);
338:             if (t_AllowTransfer_Amount < value) revert UnauthorizedLendingMarketTransfer(from, to, value);
339: 
340:             delete t_AllowTransfer_To;
341:             delete t_AllowTransfer_Amount;
342:         }
343: 
344:         super._update(from, to, value);
345:     }
```

### Impact

System restrictions can be bypassed, and the invariant is broken. Per Sherlock's judging rule, breaking an invariant is sufficient to warrant at least a Medium even if the impact is unknown.


### PoC

_No response_

### Mitigation

_No response_

# Issue M-20: Unable to increase collateral value leading to position being liquidated 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/728 

## Found by 
xiaoming90

### Summary

-

### Root Cause

-

### Internal Pre-conditions

-

### External Pre-conditions

-

### Attack Path

When the price of underlying yield tokens backing the yield strategy shares gradually decreases over time due to certain unfavorable market conditions, the collateral value of the user's positions will also decrease. In this case, the users need to top-up their collateral value to prevent being liquidated. Note that users will always want to avoid liquidation due to the loss incurred from the liquidation fee or incentive given to the liquidators, and they can only recover a portion of their assets after liquidation.

In order to do so, users can call `Router.enterPosition()` function to mint more yield strategy shares to be deposited as collateral to their position to increase its collateral value.

However, the problem is that this does not work for position that uses Pendle PT-related yield strategy shares as collateral. 

After the Pendle PT has matured, there is no way to mint new yield token (Pendle PT) as shown in Line 63 below. Thus, after maturity, there is no way for the users to top-up the collateral value of their positions.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/staking/PendlePT.sol#L63

```solidity
File: PendlePT.sol
58:     function _mintYieldTokens(
59:         uint256 assets,
60:         address /* receiver */,
61:         bytes memory data
62:     ) internal override {
63:         require(!PT.isExpired(), "Expired");
64: 
65:         PendleDepositParams memory params = abi.decode(data, (PendleDepositParams));
66:         uint256 tokenInAmount;
```

After the PT has matured, the PT rate at the Pendle protocol is fixed at 1:1 (1 PT = 1 Asset). However, that does not mean that the price of the yield strategy is fixed or will not change after maturity. Assume that after maturity, 1 PT is worth exactly 1 WETH. Here, the price of WETH continues to fluctuate based on market conditions.

As shown in Line 144 below, the price of the yield strategy shares is calculated based on the current USD price of yield token and asset token (e.g., USDC). If the price of either WETH or USDC moves, the price of the yield strategy share will move too.

In short, the price of yield strategy shares can decrease after PT has matured. Thus, there must be a way for user to top-up their position's collateral value even after PT has matured.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/AbstractYieldStrategy.sol#L144

```solidity
File: AbstractYieldStrategy.sol
118:     function price() public view override returns (uint256) {
119:         return convertToAssets(SHARE_PRECISION) * (10 ** (36 - 24)); // @audit-info SHARE_PRECISION => 1e24
120:     }
121: 
122:     /// @inheritdoc IYieldStrategy
123:     function price(address borrower) external override returns (uint256) {
124:         // Do not change the current account in this method since this method is not
125:         // authenticated and we do not want to have any unexpected side effects.
126:         address prevCurrentAccount = t_CurrentAccount;
127: 
128:         t_CurrentAccount = borrower;
129:         uint256 p = convertToAssets(SHARE_PRECISION) * (10 ** (36 - 24));
130: 
131:         t_CurrentAccount = prevCurrentAccount;
132:         return p;
133:     }
..SNIP..
471:     function convertToAssets(uint256 shares) public view virtual override returns (uint256) {
472:         uint256 yieldTokens = convertSharesToYieldToken(shares);
473:         // NOTE: rounds down on division
474:         return (yieldTokens * convertYieldTokenToAsset() * (10 ** _assetDecimals)) /
475:             (10 ** (_yieldTokenDecimals + DEFAULT_DECIMALS));
476:     }
..SNIP..
141:     function convertYieldTokenToAsset() public view returns (uint256) {
142:         // The trading module always returns a positive rate in 18 decimals so we can safely
143:         // cast to uint256
144:         (int256 rate , /* */) = TRADING_MODULE.getOraclePrice(yieldToken, asset);
145:         return uint256(rate);
146:     }
```

### Impact

Liquidation will result in a loss for users due to the liquidation fee, and they can only recover a portion of their assets after the liquidation.

Due to this issue, user will be unable to increase the collateral value of their positions, leading to their position being liquidated.

### PoC

_No response_

### Mitigation

_No response_

# Issue M-21: No slippage control during migration 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/774 

## Found by 
xiaoming90

### Summary

-

### Root Cause

-

### Internal Pre-conditions

-

### External Pre-conditions

-

### Attack Path

**Instance 1 - Exiting Position**

During migration, the `redeemData` will be set to `bytes("")` when exiting the existing positions in the previous router in Line 237 below.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/routers/AbstractLendingRouter.sol#L237

```solidity
File: AbstractLendingRouter.sol
222:     function _enterOrMigrate(
223:         address onBehalf,
224:         address vault,
225:         address asset,
226:         uint256 assetAmount,
227:         bytes memory depositData,
228:         address migrateFrom // @audit-info migrateFrom is confirmed a valid LendingRouter, NOT malicious one
229:     ) internal returns (uint256 sharesReceived) {
230:         if (migrateFrom != address(0)) {
231:             // Allow the previous lending router to repay the debt from assets held here.
232:             ERC20(asset).checkApprove(migrateFrom, assetAmount);
233:             sharesReceived = ILendingRouter(migrateFrom).balanceOfCollateral(onBehalf, vault);
234: 
235:             // Must migrate the entire position
236:             ILendingRouter(migrateFrom).exitPosition(
237:                 onBehalf, vault, address(this), sharesReceived, type(uint256).max, bytes("")
238:             );
```

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/routers/AbstractLendingRouter.sol#L108

```solidity
File: AbstractLendingRouter.sol
108:     function exitPosition(
109:         address onBehalf,
110:         address vault,
111:         address receiver, // @audit if migrate => New LendingRouter
112:         uint256 sharesToRedeem, // @audit if migrate => ILendingRouter(migrateFrom-oldLendingRouter).balanceOfCollateral(onBehalf, vault);
113:         uint256 assetToRepay, // @audit if migrate => type(uint256).max
114:         bytes calldata redeemData // @audit if migrate => empty
115:     ) external override isAuthorized(onBehalf, vault) {
```

The `redeemData` will eventually be passed into the following two (2) functions, depending on the setup:

1. `AbstractSingleSidedLP._redeemShares()`
2. `Abstract.StakingStrategy._redeemShares()`

Within the `AbstractSingleSidedLP._redeemShares()` function, the redeem data is required for slippage control in Line 166 and Line 176 below. If it is not defined, slippage control will be disabled.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/single-sided-lp/AbstractSingleSidedLP.sol#L145

```solidity
File: AbstractSingleSidedLP.sol
145:     function _redeemShares(
146:         uint256 sharesToRedeem,
147:         address sharesOwner,
148:         bool isEscrowed, // @audit-info True if there is pending withdraw request
149:         bytes memory redeemData
150:     ) internal override {
151:         RedeemParams memory params = abi.decode(redeemData, (RedeemParams));
152: 
153:         // Stores the amount of each token that has been withdrawn from the pool.
154:         uint256[] memory exitBalances;
155:         bool isSingleSided;
156:         ERC20[] memory tokens;
157:         if (isEscrowed) {
158:             // Attempt to withdraw all pending requests, tokens may be different if there
159:             // is a withdraw request.
160:             (exitBalances, tokens) = _withdrawPendingRequests(sharesOwner, sharesToRedeem);
161:             // If there are pending requests, then we are not single sided by definition
162:             isSingleSided = false;
163:         } else {
164:             isSingleSided = params.redemptionTrades.length == 0;
165:             uint256 yieldTokensBurned = convertSharesToYieldToken(sharesToRedeem);
166:             exitBalances = _unstakeAndExitPool(yieldTokensBurned, params.minAmounts, isSingleSided);
167:             tokens = TOKENS();
168:         }
169: 
170:         if (!isSingleSided) {
171:             // If not a single sided trade, will execute trades back to the primary token on
172:             // external exchanges. This method will execute EXACT_IN trades to ensure that
173:             // all of the balance in the other tokens is sold for primary.
174:             // Redemption trades are not automatically enabled on vaults since the trading module
175:             // requires explicit permission for every token that can be sold by an address.
176:             _executeRedemptionTrades(tokens, exitBalances, params.redemptionTrades);
177:         }
178:     }
```

Within the `Abstract.StakingStrategy._redeemShares()` function, the redeem data is required for slippage control in Line 100 and Line 115 below. If it is not defined, slippage control will be disabled.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/staking/AbstractStakingStrategy.sol#L82

```solidity
File: AbstractStakingStrategy.sol
082:     function _redeemShares(
083:         uint256 sharesToRedeem,
084:         address sharesOwner,
085:         bool isEscrowed,
086:         bytes memory redeemData
087:     ) internal override {
088:         if (isEscrowed) {
089:             (WithdrawRequest memory w, /* */) = withdrawRequestManager.getWithdrawRequest(address(this), sharesOwner);
090:             uint256 yieldTokensBurned = uint256(w.yieldTokenAmount) * sharesToRedeem / w.sharesAmount;
091: 
092:             (uint256 tokensClaimed, bool finalized) = withdrawRequestManager.finalizeAndRedeemWithdrawRequest({
093:                 account: sharesOwner, withdrawYieldTokenAmount: yieldTokensBurned, sharesToBurn: sharesToRedeem
094:             });
095:             if (!finalized) revert WithdrawRequestNotFinalized(w.requestId);
096: 
097:             // Trades may be required here if the borrowed token is not the same as what is
098:             // received when redeeming.
099:             if (asset != withdrawToken) {
100:                 RedeemParams memory params = abi.decode(redeemData, (RedeemParams));
101:                 Trade memory trade = Trade({
102:                     tradeType: TradeType.EXACT_IN_SINGLE,
103:                     sellToken: address(withdrawToken),
104:                     buyToken: address(asset),
105:                     amount: tokensClaimed,
106:                     limit: params.minPurchaseAmount,
107:                     deadline: block.timestamp,
108:                     exchangeData: params.exchangeData
109:                 });
110: 
111:                 _executeTrade(trade, params.dexId);
112:             }
113:         } else {
114:             uint256 yieldTokensBurned = convertSharesToYieldToken(sharesToRedeem);
115:             _executeInstantRedemption(yieldTokensBurned, redeemData);
116:         }
117:     }
```

In summary, when exiting the existing positions during the migration process, users will suffer slippage and vulnerable to sandwich/MEV attack.

**Instance 2 - Deposit to new Router**

A similar issue also occurs in Line 76, where the `depositData` is set to `bytes("")`. This means that slippage is disabled during depositing, staking, and minting of yield tokens.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/routers/AbstractLendingRouter.sol#L76

```solidity
File: AbstractLendingRouter.sol
66:     /// @inheritdoc ILendingRouter
67:     function migratePosition(
68:         address onBehalf,
69:         address vault,
70:         address migrateFrom
71:     ) public override isAuthorized(onBehalf, vault) {
72:         if (!ADDRESS_REGISTRY.isLendingRouter(migrateFrom)) revert InvalidLendingRouter();
73:         // Borrow amount is set to the amount of debt owed to the previous lending router
74:         (uint256 borrowAmount, /* */, /* */) = ILendingRouter(migrateFrom).healthFactor(onBehalf, vault);
75: 
76:         _enterPosition(onBehalf, vault, 0, borrowAmount, bytes(""), migrateFrom);
77:     }
```

### Impact

High. Loss of funds as users will suffer slippage and vulnerable to sandwich/MEV attack.

### PoC

_No response_

### Mitigation

_No response_

# Issue M-22: Convex cannot be configured for the Yield Strategy vault in Arbitrum even though Convex is available in Arbitrum 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/775 

## Found by 
0xRstStn, 0xShoonya, Atharv, Ledger\_Patrol, anchabadze, h2134, holtzzx, jasonxiale, kangaroo, lodelux, theweb3mechanic, xiaoming90

### Summary

-

### Root Cause

-

### Internal Pre-conditions

-

### External Pre-conditions

-

### Attack Path

Per the contest's README, Base and Arbitrum are in-scope for this contest. Sherlock's Judge has further confirmed this in the Discord channel.

> Q: On what chains are the smart contracts going to be deployed?
> Ethereum, in the future we will consider Base or Arbitrum

However, it was observed that Convex cannot be configured for the Yield Strategy vault in Arbitum even though Convex is available in Arbitrum.

In Line 137, the `block.chainid == CHAIN_ID_MAINNET` condition will always be false in Arbitrum and thus the `convexBooster` can never be configured.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/single-sided-lp/CurveConvex2Token.sol#L137

```solidity
File: CurveConvex2Token.sol
115:     constructor(
116:         address _token1,
117:         address _token2,
118:         address _asset,
119:         uint8 _primaryIndex,
120:         DeploymentParams memory params
121:     ) {
122:         TOKEN_1 = _token1;
123:         TOKEN_2 = _token2;
124:         ASSET = _asset;
125:         _PRIMARY_INDEX = _primaryIndex;
126: 
127:         CURVE_POOL = params.pool;
128:         CURVE_GAUGE = params.gauge;
129:         CURVE_POOL_TOKEN = ERC20(params.poolToken);
130:         CURVE_INTERFACE = params.curveInterface;
131: 
132:         // If the convex reward pool is set then get the booster and pool id, if not then
133:         // we will stake on the curve gauge directly.
134:         CONVEX_REWARD_POOL = params.convexRewardPool;
135:         address convexBooster;
136:         uint256 poolId;
137:         if (block.chainid == CHAIN_ID_MAINNET && CONVEX_REWARD_POOL != address(0)) {
138:             convexBooster = IConvexRewardPool(CONVEX_REWARD_POOL).operator();
139:             poolId = IConvexRewardPool(CONVEX_REWARD_POOL).pid();
140:         }
141: 
142:         CONVEX_POOL_ID = poolId;
143:         CONVEX_BOOSTER = convexBooster;
144:     }
```

### Impact

Medium. Core functionality is broken.


### PoC

_No response_

### Mitigation

_No response_

# Issue M-23: Incorrect Bad Debt Tracking After Full Liquidation in Lending Router 

Source: https://github.com/sherlock-audit/2025-06-notional-exponent-judging/issues/803 

## Found by 
OSSecurity, godwinudo

### Summary

The `AbstractLendingRouter` does not correctly track or enforce repayment of bad debt after a user's position is fully liquidated. When a user is liquidated and their collateral is exhausted, any remaining debt is socialized by the underlying lending protocol (Morpho), but the router clears the user's position and allows them to re-enter with no restriction or requirement to repay previously socialized debt. This results in unexpected behavior and a lack of accountability for insolvent accounts.

### Root Cause

After full liquidation, the router calls [`ADDRESS_REGISTRY.clearPosition`](https://github.com/sherlock-audit/2025-06-notional-exponent/blob/82c87105f6b32bb362d7523356f235b5b07509f9/notional-v4/src/routers/AbstractLendingRouter.sol#L169), removing all record of the user's previous debt. There is no mechanism in the router to prevent a user from opening a new position without repaying bad debt that was socialized by Morpho. The router's logic assumes the account starts fresh, which is inconsistent with the expectation that insolvent accounts should not be able to re-enter without settling prior obligations.

### Internal Pre-conditions

- The user's position is fully liquidated, resulting in zero collateral.
- The router clears the user's position in its local accounting.
- No additional tracking or enforcement of bad debt is performed by the router.

### External Pre-conditions

- Morpho socializes any remaining debt, reducing supply assets for all suppliers and setting the user's `borrowShares` to zero.

### Attack Path

1. A user is liquidated and their position is cleared in the router.
2. Any remaining debt is socialized by Morpho and not tracked by the router.
3. The user can re-enter a new position without repaying previously socialized debt, effectively escaping accountability for insolvency.

### Impact

- Insolvent users can repeatedly open new positions without ever repaying bad debt, increasing systemic risk and undermining the integrity of the protocol.
- Honest suppliers bear the cost of socialized bad debt, while insolvent users face no restrictions or consequences.
- This behavior may be exploited to repeatedly extract value from the protocol.

### PoC

Add the following PoC to `/tests/TestMorphoYieldStrategy.sol`:

```solidity
    function test_badDebtTracking_poc() public {
        address user = msg.sender;
        uint256 depositAmount = defaultDeposit;
        uint256 borrowAmount = defaultBorrow;

        // User enters a leveraged position
        _enterPosition(user, depositAmount, borrowAmount);

        // Simulate price drop to trigger liquidation
        int256 originalPrice = o.latestAnswer();
        o.setPrice(originalPrice * 0.5e18 / 1e18); // 50% price drop

        // Liquidator liquidates the user, seizing all collateral
        address liquidator = makeAddr("liquidator");
        vm.prank(owner);
        asset.transfer(liquidator, depositAmount + borrowAmount);

        vm.startPrank(liquidator);
        asset.approve(address(lendingRouter), type(uint256).max);
        uint256 sharesToLiquidate = lendingRouter.balanceOfCollateral(user, address(y));
        lendingRouter.liquidate(user, address(y), sharesToLiquidate, 0);
        vm.stopPrank();

        // User's position is now cleared
        assertEq(lendingRouter.balanceOfCollateral(user, address(y)), 0, "User position should be cleared");

        // User re-enters a new position with fresh collateral and borrow
        _enterPosition(user, depositAmount, 1);

        // Assert that user was able to re-enter without restriction
        assertGt(
            lendingRouter.balanceOfCollateral(user, address(y)), 0, "User should be able to re-enter after liquidation"
        );
    }
```

### Mitigation

- Implement logic in the router to track insolvent accounts and prevent them from opening new positions until previously socialized debt is repaid, as stated in code comments.
- Add checks to ensure that users with a history of bad debt cannot re-enter without settling prior obligations.

