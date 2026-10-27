/**
 * @name Provenance-aware indirect call targets
 * @description Resolves indirect calls while retaining storage and binding evidence.
 * @kind table
 * @id trace2fuzz/provenance-aware-indirect-call-targets
 */

import cpp
import semmle.code.cpp.pointsto.CallGraph

bindingset[prefix, component]
predicate joinPath(string prefix, string component, string joined) {
  prefix = "" and joined = component
  or
  prefix != "" and joined = prefix + "." + component
}

predicate fieldBase(FieldAccess access, Expr base) {
  base = access.getQualifier()
  or
  base = access.getAChild()
}

predicate rootedAccess(
  Expr expression, Variable root, string path, string indexPrecision
) {
  exists(VariableAccess access |
    expression = access and
    not access instanceof FieldAccess and
    root = access.getTarget() and
    path = "" and
    indexPrecision = "constant"
  )
  or
  exists(FieldAccess access, Expr qualifier, string prefix, string precision |
    expression = access and
    fieldBase(access, qualifier) and
    rootedAccess(qualifier, root, prefix, precision) and
    joinPath(prefix, access.getTarget().getName(), path) and
    indexPrecision = precision
  )
  or
  exists(ArrayExpr access, string prefix, string precision, Literal offset |
    expression = access and
    rootedAccess(access.getArrayBase(), root, prefix, precision) and
    offset = access.getArrayOffset() and
    path = prefix + "[" + offset.getValueText() + "]" and
    indexPrecision = precision
  )
  or
  exists(ArrayExpr access, string prefix, string precision |
    expression = access and
    rootedAccess(access.getArrayBase(), root, prefix, precision) and
    not access.getArrayOffset() instanceof Literal and
    path = prefix + "[*]" and
    indexPrecision = "dynamic"
  )
  or
  exists(Cast cast |
    expression = cast and
    rootedAccess(cast.getExpr(), root, path, indexPrecision)
  )
  or
  exists(AddressOfExpr address |
    expression = address and
    rootedAccess(address.getOperand(), root, path, indexPrecision)
  )
  or
  exists(PointerDereferenceExpr dereference |
    expression = dereference and
    rootedAccess(dereference.getOperand(), root, path, indexPrecision)
  )
}

predicate dispatchAccess(
  ExprCall call, Expr dispatch, Variable root, string path,
  string indexPrecision
) {
  call.getExpr().getAChild*() = dispatch and
  rootedAccess(dispatch, root, path, indexPrecision) and
  dispatch.getUnspecifiedType() instanceof FunctionPointerType and
  not exists(Expr outer |
    call.getExpr().getAChild*() = outer and
    outer != dispatch and
    outer.getAChild*() = dispatch and
    outer.getUnspecifiedType() instanceof FunctionPointerType
  )
}

predicate directAggregateFunction(
  ClassAggregateLiteral aggregate, Field field, Function callee, Expr binding
) {
  binding = aggregate.getAFieldExpr(field) and
  binding.getAChild*() = any(FunctionAccess access |
    access.getTarget() = callee
  ) and
  not exists(ClassAggregateLiteral nested |
    binding.getAChild*() = nested and
    nested.getAChild*() = any(FunctionAccess access |
      access.getTarget() = callee
    )
  )
}

predicate aggregateBinding(
  ClassAggregateLiteral aggregate, string path, Function callee, Expr binding,
  string indexPrecision, Field terminalField
) {
  exists(Field field |
    directAggregateFunction(aggregate, field, callee, binding) and
    path = field.getName() and
    indexPrecision = "constant" and
    terminalField = field
  )
  or
  exists(
    Field field, Expr child, ClassAggregateLiteral nested,
    string suffix, string precision
  |
    child = aggregate.getAFieldExpr(field) and
    child.getAChild*() = nested and
    aggregateBinding(
      nested, suffix, callee, binding, precision, terminalField
    ) and
    path = field.getName() + "." + suffix and
    indexPrecision = precision
  )
  or
  exists(
    Field field, Expr child, AggregateLiteral arrayAggregate, ArrayType arrayType,
    int index, FunctionAccess access
  |
    child = aggregate.getAFieldExpr(field) and
    child.getAChild*() = arrayAggregate and
    arrayAggregate.getUnspecifiedType() = arrayType and
    arrayAggregate.getChild(index).getAChild*() = access and
    access.getTarget() = callee and
    binding = arrayAggregate.getChild(index) and
    path = field.getName() + "[" + index.toString() + "]" and
    indexPrecision = "constant" and
    terminalField = field
  )
}

predicate aggregateMatchesVariableType(
  Variable variable, ClassAggregateLiteral aggregate
) {
  aggregate.getUnspecifiedType() = variable.getUnspecifiedType()
  or
  exists(ArrayType arrayType |
    variable.getUnspecifiedType() = arrayType and
    aggregate.getUnspecifiedType() = arrayType.getBaseType()
  )
}

predicate variableAggregateBinding(
  Variable root, string path, Function callee, Expr binding,
  string indexPrecision, Field terminalField
) {
  exists(Expr initializer, ClassAggregateLiteral aggregate |
    initializer = root.getInitializer().getExpr() and
    initializer.getAChild*() = aggregate and
    aggregateMatchesVariableType(root, aggregate) and
    aggregateBinding(
      aggregate, path, callee, binding, indexPrecision, terminalField
    )
  )
}

predicate variableArrayBinding(
  Variable root, int index, Function callee, Expr binding
) {
  exists(AggregateLiteral aggregate, ArrayType arrayType, FunctionAccess access |
    root.getInitializer().getExpr().getAChild*() = aggregate and
    aggregate.getUnspecifiedType() = arrayType and
    not exists(AggregateLiteral outer |
      root.getInitializer().getExpr().getAChild*() = outer and
      outer != aggregate and
      outer.getAChild*() = aggregate
    ) and
    binding = aggregate.getChild(index) and
    binding.getAChild*() = access and
    access.getTarget() = callee
  )
}

predicate variableStorageIdentity(Variable variable, string identity) {
  exists(LocalVariable local |
    variable = local and
    identity = local.getFunction().getQualifiedName() + "::" + local.getName()
  )
  or
  not variable instanceof LocalVariable and
  identity = variable.getQualifiedName()
}

predicate functionPointerVariableBinding(
  Variable variable, Function callee, Expr binding
) {
  not variable instanceof LocalVariable and
  variable.getUnspecifiedType() instanceof FunctionPointerType and
  (
    exists(FunctionAccess access |
      binding = variable.getInitializer().getExpr() and
      binding.getAChild*() = access and
      access.getTarget() = callee
    )
    or
    exists(AssignExpr assignment, FunctionAccess access |
      rootedAccess(assignment.getLValue(), variable, "", "constant") and
      binding = assignment.getRValue() and
      binding.getAChild*() = access and
      access.getTarget() = callee
    )
  )
}

predicate syntacticRootName(Expr expression, string name) {
  exists(Expr access |
    expression.getAChild*() = access and
    access.getAPrimaryQlClass() = "VariableAccess" and
    name = access.toString()
  )
}

predicate uniqueLocalRoot(
  Expr expression, Function function, LocalVariable root
) {
  syntacticRootName(expression, root.getName()) and
  root.getFunction() = function and
  count(LocalVariable other |
    other.getFunction() = function and
    other.getName() = root.getName()
  ) = 1
}

predicate pathHasField(Expr expression, Field field) {
  exists(FieldAccess access |
    access.getParent*() = expression and access.getTarget() = field
  )
}

predicate sameFieldPath(Expr left, Expr right) {
  count(FieldAccess access | access.getParent*() = left) =
    count(FieldAccess access | access.getParent*() = right) and
  count(FieldAccess access | access.getParent*() = left) > 0 and
  forall(Field field |
    pathHasField(left, field)
  |
    pathHasField(right, field)
  ) and
  forall(Field field |
    pathHasField(right, field)
  |
    pathHasField(left, field)
  )
}

predicate expressionInSwitchCase(Expr expression, SwitchCase switchCase) {
  expression.getEnclosingStmt() = switchCase.getAStmt()
  or
  exists(Stmt statement |
    expression.getEnclosingStmt().getParent*() = statement and
    statement = switchCase.getAStmt()
  )
}

predicate argumentUsesParameter(Expr argument, Parameter parameter) {
  exists(VariableAccess access |
    argument.getAChild*() = access and access.getTarget() = parameter
  )
}

predicate directParameterForward(Parameter source, Parameter destination) {
  exists(FunctionCall call |
    call.getEnclosingFunction() = source.getFunction() and
    call.getTarget() = destination.getFunction() and
    argumentUsesParameter(call.getArgument(destination.getIndex()), source)
  )
}

predicate forwardedParameter(Parameter source, Parameter destination) {
  source = destination
  or
  directParameterForward+(source, destination)
}

predicate parameterInvocation(Parameter parameter, ExprCall invocation) {
  invocation.getEnclosingFunction() = parameter.getFunction() and
  parameter.getUnspecifiedType() instanceof FunctionPointerType and
  exists(VariableAccess access |
    invocation.getExpr().getAChild*() = access and
    access.getTarget() = parameter
  )
}

predicate concreteCallbackArgument(
  FunctionCall registration, Parameter source, Function callee, Expr binding
) {
  registration.getTarget() = source.getFunction() and
  source.getUnspecifiedType() instanceof FunctionPointerType and
  binding = registration.getArgument(source.getIndex()) and
  exists(FunctionAccess access |
    binding.getAChild*() = access and access.getTarget() = callee
  )
}

predicate callbackParameterCandidate(
  ExprCall invocation, Function callee, Expr binding, string dispatchPath,
  string bindingPath, string storageRoot, string mechanism
) {
  exists(
    FunctionCall registration, Parameter source, Parameter destination
  |
    concreteCallbackArgument(registration, source, callee, binding) and
    forwardedParameter(source, destination) and
    parameterInvocation(destination, invocation) and
    dispatchPath = destination.getFunction().getQualifiedName() +
      "::parameter=" + destination.getIndex().toString() and
    bindingPath = source.getFunction().getQualifiedName() +
      "::parameter=" + source.getIndex().toString() and
    storageRoot = registration.getEnclosingFunction().getQualifiedName() +
      "::line=" + registration.getLocation().getStartLine().toString() and
    mechanism = "concrete-callback-argument"
  )
}

predicate externalCallbackParameter(Parameter parameter) {
  parameter.getUnspecifiedType() instanceof FunctionPointerType and
  not exists(parameter.getFunction().getDefinition())
}

predicate externalCallbackArgumentCandidate(
  FunctionCall registration, Function callee, Expr binding,
  string dispatchPath, string bindingPath, string storageRoot,
  string mechanism
) {
  exists(Parameter source, Parameter destination |
    concreteCallbackArgument(registration, source, callee, binding) and
    forwardedParameter(source, destination) and
    externalCallbackParameter(destination) and
    dispatchPath = destination.getFunction().getQualifiedName() +
      "::parameter=" + destination.getIndex().toString() and
    bindingPath = source.getFunction().getQualifiedName() +
      "::parameter=" + source.getIndex().toString() and
    storageRoot = registration.getEnclosingFunction().getQualifiedName() +
      "::line=" + registration.getLocation().getStartLine().toString() and
    mechanism = "external-callback-argument-activation"
  )
}

predicate actualRoot(FunctionCall call, Parameter parameter, Variable root) {
  call.getTarget() = parameter.getFunction() and
  rootedAccess(call.getArgument(parameter.getIndex()), root, _, _)
}

bindingset[dispatchPath, bindingPath]
predicate pathSuffix(string dispatchPath, string bindingPath) {
  dispatchPath = bindingPath
  or
  dispatchPath.regexpMatch(".*\\." + bindingPath)
}

bindingset[dispatchPath, bindingPath]
predicate dynamicPathMatch(string dispatchPath, string bindingPath) {
  dispatchPath.regexpReplaceAll("\\[\\*\\]", "") =
    bindingPath.regexpReplaceAll("\\[[0-9]+\\]", "")
}

predicate exactAggregateCandidate(
  ExprCall call, Function callee, Expr binding, string dispatchPath,
  string bindingPath, string storageRoot, string mechanism
) {
  exists(Expr dispatch, Variable root, string dispatchPrecision, string bindingPrecision |
    dispatchAccess(call, dispatch, root, dispatchPath, dispatchPrecision) and
    dispatchPrecision = "constant" and
    variableAggregateBinding(
      root, bindingPath, callee, binding, bindingPrecision, _
    ) and
    bindingPrecision = "constant" and
    dispatchPath = bindingPath and
    variableStorageIdentity(root, storageRoot) and
    mechanism = "same-storage-aggregate"
  )
  or
  exists(
    Expr dispatch, Parameter parameter, Variable actual,
    FunctionCall contextCall, string dispatchPrecision, string bindingPrecision
  |
    dispatchAccess(call, dispatch, parameter, dispatchPath, dispatchPrecision) and
    dispatchPrecision = "constant" and
    actualRoot(contextCall, parameter, actual) and
    variableAggregateBinding(
      actual, bindingPath, callee, binding, bindingPrecision, _
    ) and
    bindingPrecision = "constant" and
    dispatchPath = bindingPath and
    variableStorageIdentity(actual, storageRoot) and
    mechanism = "actual-to-formal-aggregate"
  )
}

predicate exactAssignmentCandidate(
  ExprCall call, Function callee, Expr binding, string dispatchPath,
  string bindingPath, string storageRoot, string mechanism
) {
  exists(
    Expr dispatch, LocalVariable root, AssignExpr assignment, FunctionAccess access,
    string dispatchPrecision
  |
    dispatchAccess(call, dispatch, _, dispatchPath, dispatchPrecision) and
    uniqueLocalRoot(
      assignment.getLValue(), call.getEnclosingFunction(), root
    ) and
    uniqueLocalRoot(call.getExpr(), call.getEnclosingFunction(), root) and
    sameFieldPath(assignment.getLValue(), call.getExpr()) and
    binding = assignment.getRValue() and
    binding.getAChild*() = access and
    access.getTarget() = callee and
    dispatchPrecision = "constant" and
    bindingPath = dispatchPath and
    assignment.getEnclosingFunction() = call.getEnclosingFunction() and
    assignment.getLocation().getStartLine() <= call.getLocation().getStartLine() and
    not exists(AssignExpr later |
      later != assignment and
      uniqueLocalRoot(
        later.getLValue(), call.getEnclosingFunction(), root
      ) and
      sameFieldPath(later.getLValue(), call.getExpr()) and
      later.getEnclosingFunction() = call.getEnclosingFunction() and
      later.getLocation().getStartLine() > assignment.getLocation().getStartLine() and
      later.getLocation().getStartLine() <= call.getLocation().getStartLine()
    ) and
    storageRoot = call.getEnclosingFunction().getQualifiedName() + "::" +
      root.getName() and
    mechanism = "same-storage-reaching-assignment"
  )
}

predicate variableCopySource(Variable destination, Variable source) {
  rootedAccess(destination.getInitializer().getExpr(), source, "", "constant")
}

predicate exactCopyCandidate(
  ExprCall call, Function callee, Expr binding, string dispatchPath,
  string bindingPath, string storageRoot, string mechanism
) {
  exists(
    Expr dispatch, Variable local, Variable source,
    string dispatchPrecision, string bindingPrecision
  |
    dispatchAccess(call, dispatch, local, dispatchPath, dispatchPrecision) and
    variableCopySource(local, source) and
    variableAggregateBinding(
      source, bindingPath, callee, binding, bindingPrecision, _
    ) and
    dispatchPrecision = "constant" and
    bindingPrecision = "constant" and
    dispatchPath = bindingPath and
    not exists(AssignExpr assignment |
      uniqueLocalRoot(
        assignment.getLValue(), call.getEnclosingFunction(), local
      ) and
      sameFieldPath(assignment.getLValue(), call.getExpr()) and
      assignment.getEnclosingFunction() = call.getEnclosingFunction() and
      assignment.getLocation().getStartLine() <= call.getLocation().getStartLine()
    ) and
    variableStorageIdentity(source, storageRoot) and
    mechanism = "same-storage-struct-copy"
  )
}

predicate exactReturnCandidate(
  ExprCall call, Function callee, Expr binding, string dispatchPath,
  string bindingPath, string storageRoot, string mechanism
) {
  exists(
    Expr dispatch, Variable callback, FunctionCall producerCall,
    ReturnStmt returnStatement, Variable source,
    string dispatchPrecision, string returnPath, string returnPrecision,
    string bindingPrecision
  |
    dispatchAccess(
      call, dispatch, callback, dispatchPath, dispatchPrecision
    ) and
    dispatchPath = "" and
    callback.getInitializer().getExpr().getAChild*() = producerCall and
    returnStatement.getEnclosingFunction() = producerCall.getTarget() and
    rootedAccess(
      returnStatement.getExpr(), source, returnPath, returnPrecision
    ) and
    variableAggregateBinding(
      source, bindingPath, callee, binding, bindingPrecision, _
    ) and
    returnPath = bindingPath and
    dispatchPrecision = "constant" and
    returnPrecision = "constant" and
    bindingPrecision = "constant" and
    variableStorageIdentity(source, storageRoot) and
    mechanism = "function-return-storage"
  )
}

predicate dynamicContextCandidate(
  ExprCall call, Function callee, Expr binding, string dispatchPath,
  string bindingPath, string storageRoot, string mechanism
) {
  exists(
    Expr dispatch, Parameter parameter, Variable actual,
    FunctionCall contextCall, string dispatchPrecision,
    string bindingPrecision
  |
    dispatchAccess(
      call, dispatch, parameter, dispatchPath, dispatchPrecision
    ) and
    dispatchPrecision = "dynamic" and
    actualRoot(contextCall, parameter, actual) and
    variableAggregateBinding(
      actual, bindingPath, callee, binding, bindingPrecision, _
    ) and
    dynamicPathMatch(dispatchPath, bindingPath) and
    variableStorageIdentity(actual, storageRoot) and
    mechanism = "dynamic-index-actual-to-formal"
  )
}

predicate arrayTableCandidate(
  ExprCall call, Function callee, Expr binding, string dispatchPath,
  string bindingPath, string storageRoot, string mechanism
) {
  exists(
    Expr dispatch, Variable root, int index, string dispatchPrecision
  |
    dispatchAccess(
      call, dispatch, root, dispatchPath, dispatchPrecision
    ) and
    variableArrayBinding(root, index, callee, binding) and
    bindingPath = "[" + index.toString() + "]" and
    (
      dispatchPrecision = "constant" and dispatchPath = bindingPath
      or
      dispatchPrecision = "dynamic" and
      dynamicPathMatch(dispatchPath, bindingPath)
    ) and
    variableStorageIdentity(root, storageRoot) and
    mechanism = "same-storage-array-table"
  )
}

predicate variableLifecycleCandidate(
  ExprCall call, Function callee, Expr binding, string dispatchPath,
  string bindingPath, string storageRoot, string mechanism
) {
  exists(Expr dispatch, Variable root, string dispatchPrecision |
    dispatchAccess(
      call, dispatch, root, dispatchPath, dispatchPrecision
    ) and
    dispatchPath = "" and
    dispatchPrecision = "constant" and
    functionPointerVariableBinding(root, callee, binding) and
    bindingPath = "" and
    variableStorageIdentity(root, storageRoot) and
    mechanism = "cross-function-variable-assignment"
  )
}

predicate arrayReturnBinding(
  Function producer, Function callee, Expr binding, Variable tableRoot,
  string bindingPath
) {
  exists(
    ReturnStmt returnStatement, string returnPath, string returnPrecision,
    int index
  |
    returnStatement.getEnclosingFunction() = producer and
    rootedAccess(
      returnStatement.getExpr(), tableRoot, returnPath, returnPrecision
    ) and
    variableArrayBinding(tableRoot, index, callee, binding) and
    bindingPath = "[" + index.toString() + "]" and
    (
      returnPrecision = "constant" and returnPath = bindingPath
      or
      returnPrecision = "dynamic" and
      dynamicPathMatch(returnPath, bindingPath)
    )
  )
}

predicate returnedArrayLifecycleCandidate(
  ExprCall call, Function callee, Expr binding, string dispatchPath,
  string bindingPath, string storageRoot, string mechanism
) {
  exists(
    FunctionCall producerCall, Function producer, ReturnStmt producerReturn,
    ExprCall factoryCall, Expr factoryDispatch, Variable factoryRoot,
    string factoryPath, string factoryPrecision, Function factory,
    Expr factoryBinding, Variable tableRoot, string factoryStorage,
    string tableStorage
  |
    call.getExpr().getAChild*() = producerCall and
    producerCall.getTarget() = producer and
    call.getExpr().getUnspecifiedType() instanceof FunctionPointerType and
    producerReturn.getEnclosingFunction() = producer and
    producerReturn.getExpr().getAChild*() = factoryCall and
    factoryCall.getUnspecifiedType() instanceof FunctionPointerType and
    dispatchAccess(
      factoryCall, factoryDispatch, factoryRoot, factoryPath, factoryPrecision
    ) and
    factoryPath = "" and
    factoryPrecision = "constant" and
    functionPointerVariableBinding(
      factoryRoot, factory, factoryBinding
    ) and
    arrayReturnBinding(
      factory, callee, binding, tableRoot, bindingPath
    ) and
    variableStorageIdentity(factoryRoot, factoryStorage) and
    variableStorageIdentity(tableRoot, tableStorage) and
    dispatchPath = producer.getQualifiedName() + "()" and
    storageRoot = factoryStorage + "->" + tableStorage and
    mechanism = "returned-array-via-variable-lifecycle"
  )
}

predicate directReturnedArrayLifecycleCandidate(
  ExprCall call, Function callee, Expr binding, string dispatchPath,
  string bindingPath, string storageRoot, string mechanism
) {
  exists(
    ExprCall factoryCall, Expr factoryDispatch, Variable factoryRoot,
    string factoryPath, string factoryPrecision, Function factory,
    Expr factoryBinding, Variable tableRoot, string factoryStorage,
    string tableStorage
  |
    call.getExpr().getAChild*() = factoryCall and
    factoryCall.getUnspecifiedType() instanceof FunctionPointerType and
    dispatchAccess(
      factoryCall, factoryDispatch, factoryRoot, factoryPath, factoryPrecision
    ) and
    factoryPath = "" and
    factoryPrecision = "constant" and
    functionPointerVariableBinding(
      factoryRoot, factory, factoryBinding
    ) and
    arrayReturnBinding(
      factory, callee, binding, tableRoot, bindingPath
    ) and
    variableStorageIdentity(factoryRoot, factoryStorage) and
    variableStorageIdentity(tableRoot, tableStorage) and
    dispatchPath = factoryStorage + "()" and
    storageRoot = factoryStorage + "->" + tableStorage and
    mechanism = "returned-array-via-direct-variable-lifecycle"
  )
}

predicate selectorFieldBinding(
  Function callee, Expr binding, Field terminalField, Function handler,
  SwitchCase switchCase
) {
  exists(
    FunctionCall registration, FunctionAccess callback, int argumentIndex,
    Parameter registrationSelector, Parameter dispatchSelector,
    Parameter handlerSelector, Parameter handlerVarargs,
    ExprCall dispatchCall, TargetPointsToExpr dispatchTarget,
    VariableAccess selectorAccess, VariableAccess varargsAccess,
    AssignExpr assignment, BuiltInVarArg vararg, FieldAccess fieldAccess
  |
    registration.getArgument(argumentIndex).getAChild*() = callback and
    callback.getTarget() = callee and
    binding = callback and
    registration.getTarget().isVarargs() and
    argumentIndex >= registration.getTarget().getNumberOfParameters() and
    assignment.getRValue().getAChild*() = vararg and
    handler = assignment.getEnclosingFunction() and
    handlerSelector.getFunction() = handler and
    switchCase.getSwitchStmt().getExpr().getAChild*() = selectorAccess and
    selectorAccess.getTarget() = handlerSelector and
    handlerVarargs.getFunction() = handler and
    vararg.getVAList().getAChild*() = varargsAccess and
    varargsAccess.getTarget() = handlerVarargs and
    assignment.getLValue().getAChild*() = fieldAccess and
    fieldAccess.getTarget() = terminalField and
    fieldAccess.getUnspecifiedType() instanceof FunctionPointerType and
    expressionInSwitchCase(assignment, switchCase) and
    registrationSelector.getFunction() = registration.getTarget() and
    registrationSelector.getIndex() <
      registration.getTarget().getNumberOfParameters() and
    registration.getArgument(registrationSelector.getIndex()).getValueText() =
      switchCase.getExpr().getValueText() and
    forwardedParameter(registrationSelector, dispatchSelector) and
    dispatchCall.getEnclosingFunction() = dispatchSelector.getFunction() and
    dispatchCall.getExpr() = dispatchTarget and
    dispatchTarget.pointsTo() = handler and
    argumentUsesParameter(
      dispatchCall.getArgument(handlerSelector.getIndex()), dispatchSelector
    )
  )
}

predicate selectorCandidate(
  ExprCall call, Function callee, Expr binding, string dispatchPath,
  string bindingPath, string storageRoot, string mechanism
) {
  exists(
    FieldAccess dispatchField, Field terminalField,
    Function handler, SwitchCase switchCase
  |
    call.getExpr().getAChild*() = dispatchField and
    dispatchField.getTarget() = terminalField and
    dispatchField.getUnspecifiedType() instanceof FunctionPointerType and
    selectorFieldBinding(
      callee, binding, terminalField, handler, switchCase
    ) and
    dispatchPath = terminalField.getQualifiedName() and
    bindingPath = terminalField.getQualifiedName() and
    storageRoot = handler.getQualifiedName() + "::case=" +
      switchCase.getExpr().getValueText() and
    mechanism = "selector-mediated-vararg"
  )
}

predicate directFieldBinding(
  Function callee, Expr binding, Field terminalField,
  AssignExpr assignment, Variable assignmentRoot,
  string assignmentPath, string assignmentPrecision
) {
  exists(
    FieldAccess assignedField, FunctionAccess access
  |
    assignment.getLValue().getAChild*() = assignedField and
    assignedField.getTarget() = terminalField and
    assignment.getLValue().getUnspecifiedType() instanceof FunctionPointerType and
    rootedAccess(
      assignment.getLValue(), assignmentRoot, assignmentPath,
      assignmentPrecision
    ) and
    (
      not assignmentRoot instanceof LocalVariable
      or assignmentRoot.getUnspecifiedType() instanceof PointerType
    ) and
    binding = assignment.getRValue() and
    binding.getAChild*() = access and
    access.getTarget() = callee
  )
}

predicate internalFieldDispatch(Field terminalField) {
  exists(ExprCall call, FieldAccess dispatchField |
    call.getExpr().getAChild*() = dispatchField and
    dispatchField.getTarget() = terminalField and
    dispatchField.getUnspecifiedType() instanceof FunctionPointerType
  )
}

predicate typeContainsClass(Type type, Class aggregateType) {
  type.getUnspecifiedType().resolveTypedefs() =
    aggregateType.getUnspecifiedType().resolveTypedefs()
  or
  exists(PointerType pointer |
    type.getUnspecifiedType().resolveTypedefs() = pointer and
    pointer.getBaseType().getUnspecifiedType().resolveTypedefs() =
      aggregateType.getUnspecifiedType().resolveTypedefs()
  )
  or
  exists(ReferenceType reference |
    type.getUnspecifiedType().resolveTypedefs() = reference and
    reference.getBaseType().getUnspecifiedType().resolveTypedefs() =
      aggregateType.getUnspecifiedType().resolveTypedefs()
  )
}

predicate externalFieldConsumer(Field terminalField) {
  exists(FunctionCall call, Function target, Parameter parameter |
    call.getTarget() = target and
    not exists(target.getDefinition()) and
    parameter.getFunction() = target and
    typeContainsClass(parameter.getUnspecifiedType(), terminalField.getDeclaringType())
  )
}

predicate fieldAssignmentEvidenceForDispatch(ExprCall call) {
  exists(
    FieldAccess dispatchField, Field terminalField, Function callee,
    Expr binding, AssignExpr assignment, Variable assignmentRoot,
    string assignmentPath, string assignmentPrecision
  |
    call.getExpr().getAChild*() = dispatchField and
    dispatchField.getTarget() = terminalField and
    dispatchField.getUnspecifiedType() instanceof FunctionPointerType and
    directFieldBinding(
      callee, binding, terminalField, assignment, assignmentRoot,
      assignmentPath, assignmentPrecision
    )
  )
}

predicate fieldAssignmentActivationCandidate(
  AssignExpr assignment, Function callee, Expr binding,
  string dispatchPath, string bindingPath, string storageRoot,
  string mechanism
) {
  exists(
    Field terminalField, Variable assignmentRoot,
    string assignmentPath, string assignmentPrecision
  |
    directFieldBinding(
      callee, binding, terminalField, assignment, assignmentRoot,
      assignmentPath, assignmentPrecision
    ) and
    dispatchPath = terminalField.getQualifiedName() and
    bindingPath = terminalField.getQualifiedName() and
    storageRoot = assignment.getEnclosingFunction().getQualifiedName() +
      "::" + assignmentRoot.getName() + "::" +
      terminalField.getQualifiedName() and
    (
      internalFieldDispatch(terminalField) and
      mechanism = "field-assignment-lifecycle-activation"
      or
      not internalFieldDispatch(terminalField) and
      externalFieldConsumer(terminalField) and
      mechanism = "external-field-registration-activation"
    )
  )
}

predicate forwardedParameterFieldBinding(
  Function callee, Expr binding, Field terminalField,
  FunctionCall registration,
  Parameter registrationParameter, Parameter assignmentParameter,
  AssignExpr assignment
) {
  exists(
    FunctionAccess access, int argumentIndex,
    FieldAccess assignedField, VariableAccess parameterAccess
  |
    registration.getArgument(argumentIndex).getAChild*() = access and
    access.getTarget() = callee and
    binding = access and
    registration.getTarget() = registrationParameter.getFunction() and
    registrationParameter.getIndex() = argumentIndex and
    forwardedParameter(registrationParameter, assignmentParameter) and
    assignment.getEnclosingFunction() = assignmentParameter.getFunction() and
    assignment.getLValue().getAChild*() = assignedField and
    assignedField.getTarget() = terminalField and
    assignedField.getUnspecifiedType() instanceof FunctionPointerType and
    assignment.getRValue().getAChild*() = parameterAccess and
    parameterAccess.getTarget() = assignmentParameter
  )
}

predicate forwardedParameterFieldCandidate(
  Call call, Function callee, Expr binding, string dispatchPath,
  string bindingPath, string storageRoot, string mechanism
) {
  exists(
    ExprCall dispatchCall, FieldAccess dispatchField, Field terminalField,
    FunctionCall registration,
    Parameter registrationParameter, Parameter assignmentParameter,
    AssignExpr assignment
  |
    call = registration and
    dispatchCall.getExpr().getAChild*() = dispatchField and
    dispatchField.getTarget() = terminalField and
    dispatchField.getUnspecifiedType() instanceof FunctionPointerType and
    forwardedParameterFieldBinding(
      callee, binding, terminalField, registration, registrationParameter,
      assignmentParameter, assignment
    ) and
    dispatchPath = terminalField.getQualifiedName() and
    bindingPath = terminalField.getQualifiedName() and
    storageRoot = registrationParameter.getFunction().getQualifiedName() +
      "::parameter=" + registrationParameter.getIndex().toString() and
    mechanism = "forwarded-parameter-lifecycle-activation"
  )
}

predicate forwardedParameterFieldEvidenceForDispatch(ExprCall call) {
  exists(
    FieldAccess dispatchField, Field terminalField, Function callee,
    Expr binding, FunctionCall registration,
    Parameter registrationParameter, Parameter assignmentParameter,
    AssignExpr assignment
  |
    call.getExpr().getAChild*() = dispatchField and
    dispatchField.getTarget() = terminalField and
    dispatchField.getUnspecifiedType() instanceof FunctionPointerType and
    forwardedParameterFieldBinding(
      callee, binding, terminalField, registration, registrationParameter,
      assignmentParameter, assignment
    )
  )
}

predicate strongCandidateForCall(ExprCall call) {
  exists(Function callee, Expr binding, string dispatchPath, string bindingPath,
    string storageRoot, string mechanism |
    exactAggregateCandidate(
      call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
    )
    or
    exactAssignmentCandidate(
      call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
    )
    or
    exactCopyCandidate(
      call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
    )
    or
    exactReturnCandidate(
      call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
    )
    or
    selectorCandidate(
      call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
    )
    or
    arrayTableCandidate(
      call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
    )
    or
    callbackParameterCandidate(
      call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
    )
  )
}

predicate contextCandidateForCall(ExprCall call) {
  exists(Function callee, Expr binding, string dispatchPath, string bindingPath,
    string storageRoot, string mechanism |
    dynamicContextCandidate(
      call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
    )
  )
}

predicate pointsToCandidate(
  ExprCall call, Function callee, Expr binding, string dispatchPath,
  string bindingPath, string storageRoot, string mechanism
) {
  exists(TargetPointsToExpr target, Expr dispatch, Variable root, string precision |
    call.getExpr() = target and
    target.pointsTo() = callee and
    binding = target and
    mechanism = "codeql-points-to" and
    dispatchAccess(call, dispatch, root, dispatchPath, precision) and
    bindingPath = dispatchPath and
    variableStorageIdentity(root, storageRoot)
  )
  or
  exists(TargetPointsToExpr target |
    call.getExpr() = target and
    target.pointsTo() = callee and
    binding = target and
    mechanism = "codeql-points-to" and
    not exists(Expr d, Variable r, string p, string q |
      dispatchAccess(call, d, r, p, q)
    ) and
    dispatchPath = call.getExpr().toString() and
    bindingPath = dispatchPath and
    storageRoot = ""
  )
}

bindingset[fullPath, prefix]
predicate properPathPrefix(string fullPath, string prefix) {
  exists(string suffix |
    suffix != "" and fullPath = prefix + "." + suffix
  )
}

bindingset[call, dispatchRoot, dispatchPath]
predicate dispatchSourceRoot(
  ExprCall call, Variable dispatchRoot, string dispatchPath,
  Variable sourceRoot
) {
  sourceRoot = dispatchRoot
  or
  exists(
    AssignExpr assignment, string assignedPath,
    string assignedPrecision, string sourcePath, string sourcePrecision
  |
    assignment.getEnclosingFunction() = call.getEnclosingFunction() and
    assignment.getLocation().getStartLine() <= call.getLocation().getStartLine() and
    rootedAccess(
      assignment.getLValue(), dispatchRoot, assignedPath, assignedPrecision
    ) and
    assignedPrecision = "constant" and
    rootedAccess(
      assignment.getRValue(), sourceRoot, sourcePath, sourcePrecision
    ) and
    sourcePath = "" and
    sourcePrecision = "constant" and
    properPathPrefix(dispatchPath, assignedPath)
  )
}

predicate requiredBitGuard(
  ExprCall call, Variable guardedRoot, Field guardField, int mask
) {
  exists(
    IfStmt guard, NotExpr negation, BitwiseAndExpr bitwiseAnd,
    FieldAccess guardAccess, Literal maskLiteral,
    string guardPath, string guardPrecision
  |
    guard.getCondition() = negation and
    negation.getAChild*() = bitwiseAnd and
    bitwiseAnd.getAChild*() = guardAccess and
    not exists(FieldAccess outerAccess |
      bitwiseAnd.getAChild*() = outerAccess and
      outerAccess != guardAccess and
      outerAccess.getAChild*() = guardAccess
    ) and
    guardAccess.getTarget() = guardField and
    rootedAccess(
      guardAccess, guardedRoot, guardPath, guardPrecision
    ) and
    guardPrecision = "constant" and
    bitwiseAnd.getAChild*() = maskLiteral and
    mask = maskLiteral.getValue().toInt() and
    mask > 0 and
    call.getEnclosingStmt().getParent*() = guard.getElse()
  )
}

predicate variableAggregateFieldValue(
  Variable root, Field field, int value
) {
  exists(
    Expr initializer, ClassAggregateLiteral aggregate,
    Field aggregateField, Expr fieldExpression
  |
    initializer = root.getInitializer().getExpr() and
    initializer.getAChild*() = aggregate and
    aggregateMatchesVariableType(root, aggregate) and
    aggregateField.getQualifiedName() = field.getQualifiedName() and
    fieldExpression = aggregate.getAFieldExpr(aggregateField) and
    value = fieldExpression.getValue().toInt()
  )
}

predicate variableAggregateFieldValueByName(
  Variable root, string fieldName, int value
) {
  exists(Field field |
    field.getQualifiedName() = fieldName and
    variableAggregateFieldValue(root, field, value)
  )
}

bindingset[call, dispatchRoot, dispatchPath, tableRoot]
predicate schemaGuardCompatible(
  ExprCall call, Variable dispatchRoot, string dispatchPath,
  Variable tableRoot
) {
  not exists(
    Variable sourceRoot, string guardFieldName, int mask
  |
    dispatchSourceRoot(
      call, dispatchRoot, dispatchPath, sourceRoot
    ) and
    exists(Field guardField |
      requiredBitGuard(call, sourceRoot, guardField, mask) and
      guardFieldName = guardField.getQualifiedName()
    ) and
    not exists(int aggregateValue |
      variableAggregateFieldValueByName(
        tableRoot, guardFieldName, aggregateValue
      ) and
      aggregateValue.bitAnd(mask) != 0
    )
  )
}

predicate schemaCandidate(
  ExprCall call, Function callee, Expr binding, string dispatchPath,
  string bindingPath, string storageRoot, string mechanism, string precision
) {
  exists(
    Expr dispatch, Variable dispatchRoot, Variable tableRoot,
    Field terminalField,
    string dispatchPrecision, string bindingPrecision
  |
    dispatchAccess(
      call, dispatch, dispatchRoot, dispatchPath, dispatchPrecision
    ) and
    variableAggregateBinding(
      tableRoot, bindingPath, callee, binding, bindingPrecision, terminalField
    ) and
    pathHasField(dispatch, terminalField) and
    pathSuffix(dispatchPath, bindingPath) and
    schemaGuardCompatible(call, dispatchRoot, dispatchPath, tableRoot) and
    variableStorageIdentity(tableRoot, storageRoot) and
    mechanism = "complete-path-schema" and
    (
      dispatchPrecision = "constant" and
      bindingPrecision = "constant" and
      precision = "constant"
      or
      (dispatchPrecision = "dynamic" or bindingPrecision = "dynamic") and
      precision = "dynamic"
    )
  )
}

predicate structuredFieldEvidenceForCall(ExprCall call) {
  exists(
    Function callee, Expr binding, string dispatchPath, string bindingPath,
    string storageRoot, string mechanism, string precision
  |
    schemaCandidate(
      call, callee, binding, dispatchPath, bindingPath, storageRoot,
      mechanism, precision
    )
  )
  or
  fieldAssignmentEvidenceForDispatch(call)
  or
  forwardedParameterFieldEvidenceForDispatch(call)
}

predicate candidate(
  Call call, Function callee, Expr binding, string dispatchPath,
  string bindingPath, string storageRoot, string evidenceTier,
  string mechanism
) {
  exactAggregateCandidate(
    call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
  ) and
  evidenceTier = "storage_exact"
  or
  exactAssignmentCandidate(
    call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
  ) and
  evidenceTier = "storage_exact"
  or
  exactCopyCandidate(
    call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
  ) and
  evidenceTier = "storage_exact"
  or
  exactReturnCandidate(
    call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
  ) and
  evidenceTier = "storage_exact"
  or
  dynamicContextCandidate(
    call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
  ) and
  evidenceTier = "possible"
  or
  selectorCandidate(
    call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
  ) and
  evidenceTier = "selector_binding"
  or
  arrayTableCandidate(
    call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
  ) and
  evidenceTier = "storage_exact"
  or
  callbackParameterCandidate(
    call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
  ) and
  evidenceTier = "storage_exact"
  or
  externalCallbackArgumentCandidate(
    call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
  ) and
  evidenceTier = "lifecycle_binding"
  or
  variableLifecycleCandidate(
    call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
  ) and
  evidenceTier = "lifecycle_binding"
  or
  returnedArrayLifecycleCandidate(
    call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
  ) and
  evidenceTier = "lifecycle_binding"
  or
  directReturnedArrayLifecycleCandidate(
    call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
  ) and
  evidenceTier = "lifecycle_binding"
  or
  forwardedParameterFieldCandidate(
    call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
  ) and
  evidenceTier = "lifecycle_binding"
  or
  pointsToCandidate(
    call, callee, binding, dispatchPath, bindingPath, storageRoot, mechanism
  ) and
  not strongCandidateForCall(call) and
  not contextCandidateForCall(call) and
  not structuredFieldEvidenceForCall(call) and
  evidenceTier = "provenance"
  or
  exists(string precision |
    schemaCandidate(
      call, callee, binding, dispatchPath, bindingPath, storageRoot,
      mechanism, precision
    ) and
    not strongCandidateForCall(call) and
    not contextCandidateForCall(call) and
    (
      precision = "constant" and evidenceTier = "schema_binding"
      or
      precision = "dynamic" and evidenceTier = "possible"
    )
  )
}

predicate callTargetText(Call call, string text) {
  exists(ExprCall indirect |
    call = indirect and text = indirect.getExpr().toString()
  )
  or
  exists(FunctionCall direct |
    call = direct and text = direct.getTarget().getQualifiedName()
  )
}

predicate resultCandidate(
  Expr anchor, Function caller, Function callee, Expr binding,
  string dispatchPath, string bindingPath, string storageRoot,
  string evidenceTier, string mechanism, string targetExpression
) {
  exists(Call call |
    anchor = call and
    call.getEnclosingFunction() = caller and
    candidate(
      call, callee, binding, dispatchPath, bindingPath, storageRoot,
      evidenceTier, mechanism
    ) and
    callTargetText(call, targetExpression)
  )
  or
  exists(AssignExpr assignment |
    anchor = assignment and
    assignment.getEnclosingFunction() = caller and
    fieldAssignmentActivationCandidate(
      assignment, callee, binding, dispatchPath, bindingPath,
      storageRoot, mechanism
    ) and
    evidenceTier = "lifecycle_binding" and
    targetExpression = assignment.getLValue().toString()
  )
}

from
  Expr anchor, Function caller, Function callee, Expr binding,
  string dispatchPath, string bindingPath, string storageRoot,
  string evidenceTier, string mechanism, string targetExpression
where
  resultCandidate(
    anchor, caller, callee, binding, dispatchPath, bindingPath,
    storageRoot, evidenceTier, mechanism, targetExpression
  )
select
  callee.getName() as callee_name,
  callee.getQualifiedName() as callee_qualified_name,
  callee.getLocation().getFile().getRelativePath() as callee_file,
  callee.getLocation().getStartLine() as callee_line,
  caller.getName() as caller_name,
  caller.getQualifiedName() as caller_qualified_name,
  anchor.getLocation().getFile().getRelativePath() as callsite_file,
  anchor.getLocation().getStartLine() as callsite_line,
  anchor.getLocation().getStartColumn() as callsite_column,
  targetExpression as target_expression,
  evidenceTier as evidence_tier,
  mechanism as mechanism_kind,
  storageRoot as storage_root,
  dispatchPath as dispatch_path,
  bindingPath as binding_path,
  binding.getLocation().getFile().getRelativePath() as binding_file,
  binding.getLocation().getStartLine() as binding_line
